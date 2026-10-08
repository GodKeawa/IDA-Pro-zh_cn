// ida_hook.cpp
// IDA Pro Linux 汉化 LD_PRELOAD Hook
// 用法: LD_LIBRARY_PATH=/opt/ida-pro LD_PRELOAD=/opt/ida-pro/ida_lang_hook.so /opt/ida-pro/ida
//
// 翻译文件格式 (ida_lang.txt):
//   L"原文",L"译文",
// 翻译文件查找顺序:
//   1. $IDA_LANG 环境变量指定的路径
//   2. so文件同目录下的 ida_lang.txt
//   3. ~/.config/ida/ida_lang.txt
//
// 未命中的字符串会在IDA退出时写入 /tmp/ida_missing_translations.txt

#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstddef>
#include <stdint.h>
#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <mutex>
#include <limits.h>
#include <unistd.h>

// ═══════════════════════════════════════════════════════════════════════════
// QString ABI (Qt6 x86-64, IDA 9.4)
//
// 内存布局:
//   +0x00  d       (QArrayData*)
//   +0x08  ptr     (char16_t*)
//   +0x10  size    (qsizetype)
//
// 控件setter只用于不会参与IDA对象查找的文案；菜单文字在绘制时替换。
// 不拦截Qt全局翻译入口，也不修改QAction/QMenu保存的身份文本。
// ═══════════════════════════════════════════════════════════════════════════
struct QString {
    void*     d;
    uint16_t* ptr;
    ptrdiff_t size;
};

// Qt6中QRect/QSize均为可按值返回的简单整数聚合体。
struct QRect {
    int x1, y1, x2, y2;
};
struct QSize {
    int width, height;
};

// ═══════════════════════════════════════════════════════════════════════════
// 翻译表（运行时从文件加载）
// ═══════════════════════════════════════════════════════════════════════════

// 解析单个转义序列，写入dst，返回消耗的src字节数
static int parse_escape(const char* src, char* dst, int& dlen) {
    if (src[0] != '\\') { dst[dlen++] = src[0]; return 1; }
    switch (src[1]) {
        case 'n':  dst[dlen++] = '\n'; return 2;
        case 't':  dst[dlen++] = '\t'; return 2;
        case 'r':  dst[dlen++] = '\r'; return 2;
        case '\\': dst[dlen++] = '\\'; return 2;
        case '"':  dst[dlen++] = '"';  return 2;
        default:   dst[dlen++] = src[1]; return 2;
    }
}

static std::unordered_set<std::string>& known_ui_outputs() {
    // 堆上保存到进程结束，避免LD_PRELOAD构造/析构顺序影响。
    static auto* values = new std::unordered_set<std::string>();
    return *values;
}

// 从 L"..." 提取内容，返回提取的字符串，pos更新到结束引号之后
static std::string extract_lstring(const std::string& line, size_t& pos) {
    // 跳过空白和 L
    while (pos < line.size() && (line[pos]==' '||line[pos]=='\t')) pos++;
    if (pos >= line.size()) return "";
    if (line[pos] == 'L') pos++;
    if (pos >= line.size() || line[pos] != '"') return "";
    pos++; // 跳过开头 "

    std::string result;
    while (pos < line.size() && line[pos] != '"') {
        if (line[pos] == '\\' && pos+1 < line.size()) {
            char tmp[4]; int dlen = 0;
            pos += parse_escape(line.c_str() + pos, tmp, dlen);
            result.append(tmp, dlen);
        } else {
            result += line[pos++];
        }
    }
    if (pos < line.size()) pos++; // 跳过结尾 "
    return result;
}

static std::string get_so_dir() {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return "";
    
    void* self_addr = (void*)(uintptr_t)get_so_dir;
    char line[512];
    std::string result;
    
    while (fgets(line, sizeof(line), f)) {
        unsigned long start, end;
        char perm[8], path[400] = {};
        // 格式: start-end perms offset dev inode path
        if (sscanf(line, "%lx-%lx %s %*s %*s %*s %399s",
                   &start, &end, perm, path) >= 3) {
            if ((uintptr_t)self_addr >= start &&
                (uintptr_t)self_addr <  end   &&
                path[0] == '/') {
                std::string p(path);
                size_t slash = p.rfind('/');
                if (slash != std::string::npos)
                    result = p.substr(0, slash);
                break;
            }
        }
    }
    fclose(f);
    return result;
}

static const std::unordered_map<std::string, std::string>& get_trans() {
    static std::unordered_map<std::string, std::string> m;
    static bool loaded = false;
    if (loaded) return m;
    loaded = true;

    // 候选路径列表
    std::string so_dir = get_so_dir();
    fprintf(stdout, "[ida_lang_hook] [INFO] We are in: %s\n", so_dir.c_str());
    const char* env_path = getenv("IDA_LANG");
    const char* home = getenv("HOME");
    
    std::string candidate_sodir  = so_dir.empty() ? "" : so_dir + "/ida_lang.txt";
    std::string candidate_home   = home ? std::string(home) + "/.config/ida/ida_lang.txt" : "";

    const char* candidates[] = {
        env_path,
        candidate_sodir.empty()  ? nullptr : candidate_sodir.c_str(),
        candidate_home.empty()   ? nullptr : candidate_home.c_str(),
    };

    std::ifstream f;
    const char* used_path = nullptr;
    for (int i = 0; i < 3; i++) {
        if (!candidates[i] || candidates[i][0] == '\0') continue;
        fprintf(stdout, "[ida_lang_hook] [INFO] Checking: %s\n", candidates[i]);
        f.open(candidates[i]);
        if (f.is_open()) { used_path = candidates[i]; break; }
    }

    if (!f.is_open()) {
        fprintf(stderr, "[ida_lang_hook] WARNING: no translation file found\n");
        fprintf(stderr, "[ida_lang_hook]   tried: %s\n",
                candidate_sodir.empty() ? "(none)" : candidate_sodir.c_str());
        fprintf(stderr, "[ida_lang_hook]   set $IDA_LANG to override path\n");
        return m;
    }

    fprintf(stderr, "[ida_lang_hook] loading: %s\n", used_path);

    std::string line;
    int count = 0, skipped = 0;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue; // 支持注释行
        size_t pos = 0;
        std::string key = extract_lstring(line, pos);
        if (key.empty()) { skipped++; continue; }
        // 跳过逗号
        while (pos < line.size() && (line[pos]==' '||line[pos]==','||line[pos]=='\t')) pos++;
        std::string val = extract_lstring(line, pos);
        if (val.empty()) { skipped++; continue; }
        m[key] = val;
        known_ui_outputs().insert(val);
        count++;
    }

    fprintf(stderr, "[ida_lang_hook] loaded %d entries (%d skipped)\n", count, skipped);
    return m;
}

// ═══════════════════════════════════════════════════════════════════════════
// 未命中记录
// ═══════════════════════════════════════════════════════════════════════════
static std::set<std::string>  g_missing;
static std::mutex             g_missing_mutex;

static bool contains_cjk_utf8(const char* text) {
    const unsigned char* s = (const unsigned char*)text;
    for (size_t i = 0; s[i];) {
        uint32_t cp;
        if (s[i] < 0x80) { cp = s[i++]; }
        else if ((s[i] & 0xE0) == 0xC0 && s[i + 1]) {
            cp = ((s[i] & 0x1F) << 6) | (s[i + 1] & 0x3F); i += 2;
        } else if ((s[i] & 0xF0) == 0xE0 && s[i + 1] && s[i + 2]) {
            cp = ((s[i] & 0x0F) << 12) | ((s[i + 1] & 0x3F) << 6) | (s[i + 2] & 0x3F); i += 3;
        } else if ((s[i] & 0xF8) == 0xF0 && s[i + 1] && s[i + 2] && s[i + 3]) {
            cp = ((s[i] & 0x07) << 18) | ((s[i + 1] & 0x3F) << 12)
               | ((s[i + 2] & 0x3F) << 6) | (s[i + 3] & 0x3F); i += 4;
        } else {
            i++;
            continue;
        }
        if ((cp >= 0x3400 && cp <= 0x9FFF) || (cp >= 0xF900 && cp <= 0xFAFF))
            return true;
    }
    return false;
}

static bool is_runtime_noise(const char* text) {
    if (known_ui_outputs().find(text) != known_ui_outputs().end()) return true;
    if (contains_cjk_utf8(text)) return true;
    if (strstr(text, "/home/") != nullptr) return true;
    const char* prefixes[] = {
        "IDA - ", "IDA v", "Version ", "Navigator Scale: ", "Disk: ",
        "Packing the database\n", "Unpacking the database\n",
    };
    for (const char* prefix : prefixes)
        if (strncmp(text, prefix, strlen(prefix)) == 0) return true;

    // 地址、大小和纯数字等会随数据库变化，不应进入可维护词典。
    bool has_letter = false;
    for (const unsigned char* p = (const unsigned char*)text; *p; ++p) {
        if ((*p >= 'G' && *p <= 'Z') || (*p >= 'g' && *p <= 'z')) {
            has_letter = true;
            break;
        }
    }
    return !has_letter;
}

static void record_missing(const char* sourceText) {
    if (!sourceText || sourceText[0] == '\0') return;
    // 过滤纯空白和单字符（太多噪音）
    if (strlen(sourceText) <= 1) return;
    if (is_runtime_noise(sourceText)) return;
    std::lock_guard<std::mutex> lock(g_missing_mutex);
    g_missing.insert(sourceText);
}

// ═══════════════════════════════════════════════════════════════════════════
// QString 构造工具与解析工具
// ═══════════════════════════════════════════════════════════════════════════
static std::string qstring_to_utf8(const QString* qs) {
    if (!qs || !qs->ptr || qs->size <= 0) return "";
    const uint16_t* data = qs->ptr;
    
    std::string res;
    for (ptrdiff_t i = 0; i < qs->size; i++) {
        uint16_t wc = data[i];
        if (wc < 0x80) {
            res += (char)wc;
        } else if (wc < 0x800) {
            res += (char)(0xC0 | (wc >> 6));
            res += (char)(0x80 | (wc & 0x3F));
        } else if (wc >= 0xD800 && wc < 0xDC00 && i + 1 < qs->size) {
            uint16_t wc2 = data[++i];
            uint32_t cp = 0x10000 + (((wc & 0x3FF) << 10) | (wc2 & 0x3FF));
            res += (char)(0xF0 | (cp >> 18));
            res += (char)(0x80 | ((cp >> 12) & 0x3F));
            res += (char)(0x80 | ((cp >> 6) & 0x3F));
            res += (char)(0x80 | (cp & 0x3F));
        } else {
            res += (char)(0xE0 | (wc >> 12));
            res += (char)(0x80 | ((wc >> 6) & 0x3F));
            res += (char)(0x80 | (wc & 0x3F));
        }
    }
    return res;
}

typedef void (*qstring_utf16_ctor_fn)(QString*, const uint16_t*, ptrdiff_t);
static qstring_utf16_ctor_fn g_qstring_utf16_ctor = nullptr;
static void resolve_qt_symbols();

static bool fill_qstring(QString* out, const char* utf8) {
    resolve_qt_symbols();
    if (!g_qstring_utf16_ctor) return false;

    // UTF-8 -> UTF-16LE
    size_t maxlen = strlen(utf8) * 2 + 2;
    uint16_t* tmp = (uint16_t*)alloca(maxlen * sizeof(uint16_t));
    size_t i = 0, j = 0;
    const unsigned char* s = (const unsigned char*)utf8;
    while (s[i]) {
        uint32_t cp;
        if      (s[i] < 0x80) { cp = s[i++]; }
        else if (s[i] < 0xE0) { cp = (s[i]&0x1F)<<6  | (s[i+1]&0x3F); i+=2; }
        else if (s[i] < 0xF0) { cp = (s[i]&0x0F)<<12 | (s[i+1]&0x3F)<<6  | (s[i+2]&0x3F); i+=3; }
        else                   { cp = (s[i]&0x07)<<18 | (s[i+1]&0x3F)<<12 | (s[i+2]&0x3F)<<6 | (s[i+3]&0x3F); i+=4; }
        if (cp < 0x10000) {
            tmp[j++] = (uint16_t)cp;
        } else {
            cp -= 0x10000;
            tmp[j++] = (uint16_t)(0xD800 | (cp >> 10));
            tmp[j++] = (uint16_t)(0xDC00 | (cp & 0x3FF));
        }
    }
    // 交给IDA自带的Qt6构造QString，避免手工构造其私有引用计数数据。
    g_qstring_utf16_ctor(out, tmp, (ptrdiff_t)j);
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════
// 原始函数指针（sret调用约定）
// ═══════════════════════════════════════════════════════════════════════════
typedef void (*qbtn_settext_fn)(void*, const QString*);
typedef void (*qlabel_settext_fn)(void*, const QString*);
typedef void (*qwidget_setwndtitle_fn)(void*, const QString*);
typedef void (*qwidget_settooltip_fn)(void*, const QString*);
typedef void (*qaction_settooltip_fn)(void*, const QString*);
typedef void (*qgroupbox_settitle_fn)(void*, const QString*);
typedef void (*qdockwidget_setwndtitle_fn)(void*, const QString*);
typedef void (*qtabwidget_settabtext_fn)(void*, int, const QString*);

typedef void (*qmsgbox_settext_fn)(void*, const QString*);
typedef void (*qpainter_drawtext_rect_fn)(void*, const void*, int, const QString*, void*);
typedef int (*qfontmetrics_advance_fn)(const void*, const QString*, int);
typedef QRect (*qfontmetrics_bounding_fn)(const void*, const QString*);
typedef QRect (*qfontmetrics_bounding_rect_fn)(
    const void*, const QRect*, int, const QString*, int, int*);
typedef QSize (*qfontmetrics_size_fn)(const void*, int, const QString*, int, int*);
typedef void (*qfontmetrics_elided_fn)(
    QString*, const void*, const QString*, int, int, int);
typedef void (*qfontmetricsf_elided_fn)(
    QString*, const void*, const QString*, int, double, int);
typedef void (*qlineedit_setplaceholder_fn)(void*, const QString*);
typedef void (*qtextedit_setplaceholder_fn)(void*, const QString*);
typedef void (*qcombobox_setitemtext_fn)(void*, int, const QString*);
typedef void (*qstatusbar_showmessage_fn)(void*, const QString*, int);
typedef void (*qsystray_settooltip_fn)(void*, const QString*);
typedef void (*qwizard_settitle_fn)(void*, const QString*);

static qbtn_settext_fn        g_qbtn_settext     = nullptr;
static qlabel_settext_fn      g_qlabel_settext   = nullptr;
static qwidget_setwndtitle_fn g_qwidget_setwndtitle = nullptr;
static qwidget_settooltip_fn  g_qwidget_settooltip = nullptr;
static qaction_settooltip_fn  g_qact_settooltip  = nullptr;
static qgroupbox_settitle_fn  g_qgrpbox_settitle = nullptr;
static qtabwidget_settabtext_fn g_qtabwdg_settabtext = nullptr;

static qmsgbox_settext_fn          g_qmsgbox_settext        = nullptr;
static qpainter_drawtext_rect_fn   g_qpainter_drawtext_rect = nullptr;
static qfontmetrics_advance_fn     g_qfontmetrics_advance = nullptr;
static qfontmetrics_bounding_fn    g_qfontmetrics_bounding = nullptr;
static qfontmetrics_bounding_rect_fn g_qfontmetrics_bounding_rect = nullptr;
static qfontmetrics_size_fn        g_qfontmetrics_size = nullptr;
static qfontmetrics_elided_fn      g_qfontmetrics_elided = nullptr;
static qfontmetricsf_elided_fn     g_qfontmetricsf_elided = nullptr;
static qlineedit_setplaceholder_fn g_qlineedit_setplaceholder = nullptr;
static qtextedit_setplaceholder_fn g_qtextedit_setplaceholder = nullptr;
static qcombobox_setitemtext_fn    g_qcombo_setitemtext     = nullptr;
static qsystray_settooltip_fn      g_qsystray_settooltip    = nullptr;
static qwizard_settitle_fn         g_qwizard_settitle       = nullptr;
static qwidget_settooltip_fn       g_qact_seticontext       = nullptr;
static qwidget_settooltip_fn       g_qact_setstatustip      = nullptr;
static qwidget_settooltip_fn       g_qact_setwhatsthis      = nullptr;
static qwidget_settooltip_fn       g_qwidget_setstatustip   = nullptr;
static qwidget_settooltip_fn       g_qwidget_setwhatsthis   = nullptr;
static qwidget_settooltip_fn       g_qplaintext_setplaceholder = nullptr;
static qwidget_settooltip_fn       g_qcommandlink_setdescription = nullptr;
static qtabwidget_settabtext_fn    g_qtabbar_settabtext     = nullptr;
static qtabwidget_settabtext_fn    g_qtabbar_settabtooltip  = nullptr;
static qtabwidget_settabtext_fn    g_qtabbar_settabwhatsthis = nullptr;
static qtabwidget_settabtext_fn    g_qtoolbox_setitemtext   = nullptr;
static qtabwidget_settabtext_fn    g_qtoolbox_setitemtooltip = nullptr;
static qtabwidget_settabtext_fn    g_qfiledialog_setlabeltext = nullptr;
static qwidget_settooltip_fn       g_qinputdialog_setlabeltext = nullptr;
static qwidget_settooltip_fn       g_qinputdialog_setoktext = nullptr;
static qwidget_settooltip_fn       g_qinputdialog_setcanceltext = nullptr;
static qwidget_settooltip_fn       g_qmsgbox_setinformative = nullptr;
static qwidget_settooltip_fn       g_qmsgbox_setdetailed    = nullptr;
static qwidget_settooltip_fn       g_qmsgbox_setwindowtitle = nullptr;
static qtabwidget_settabtext_fn    g_qmsgbox_setbuttontext  = nullptr;
static qwidget_settooltip_fn       g_qprogress_setlabeltext = nullptr;
static qwidget_settooltip_fn       g_qprogress_setcanceltext = nullptr;
static qwidget_settooltip_fn       g_qwizard_setsubtitle    = nullptr;
static qtabwidget_settabtext_fn    g_qwizard_setbuttontext  = nullptr;
static qstatusbar_showmessage_fn   g_qstatusbar_showmessage = nullptr;

// 预加载库的构造函数可能早于Qt库初始化；首次真正进入钩子时再解析符号。
static void resolve_qt_symbols() {
    static std::once_flag once;
    std::call_once(once, [] {
        g_qstring_utf16_ctor = (qstring_utf16_ctor_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QStringC1EPKNS_5QCharEx");
        g_qbtn_settext = (qbtn_settext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT15QAbstractButton7setTextERKNS_7QStringE");
        g_qlabel_settext = (qlabel_settext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT6QLabel7setTextERKNS_7QStringE");
        g_qwidget_setwndtitle = (qwidget_setwndtitle_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QWidget14setWindowTitleERKNS_7QStringE");
        g_qwidget_settooltip = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QWidget10setToolTipERKNS_7QStringE");
        g_qact_settooltip = (qaction_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QAction10setToolTipERKNS_7QStringE");
        g_qgrpbox_settitle = (qgroupbox_settitle_fn)dlsym(RTLD_NEXT,
            "_ZN2QT9QGroupBox8setTitleERKNS_7QStringE");
        g_qtabwdg_settabtext = (qtabwidget_settabtext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT10QTabWidget10setTabTextEiRKNS_7QStringE");
        g_qmsgbox_settext = (qmsgbox_settext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT11QMessageBox7setTextERKNS_7QStringE");
        g_qpainter_drawtext_rect = (qpainter_drawtext_rect_fn)dlsym(RTLD_NEXT,
            "_ZN2QT8QPainter8drawTextERKNS_5QRectEiRKNS_7QStringEPS1_");
        g_qfontmetrics_advance = (qfontmetrics_advance_fn)dlsym(RTLD_NEXT,
            "_ZNK2QT12QFontMetrics17horizontalAdvanceERKNS_7QStringEi");
        g_qfontmetrics_bounding = (qfontmetrics_bounding_fn)dlsym(RTLD_NEXT,
            "_ZNK2QT12QFontMetrics12boundingRectERKNS_7QStringE");
        g_qfontmetrics_bounding_rect = (qfontmetrics_bounding_rect_fn)dlsym(RTLD_NEXT,
            "_ZNK2QT12QFontMetrics12boundingRectERKNS_5QRectEiRKNS_7QStringEiPi");
        g_qfontmetrics_size = (qfontmetrics_size_fn)dlsym(RTLD_NEXT,
            "_ZNK2QT12QFontMetrics4sizeEiRKNS_7QStringEiPi");
        g_qfontmetrics_elided = (qfontmetrics_elided_fn)dlsym(RTLD_NEXT,
            "_ZNK2QT12QFontMetrics10elidedTextERKNS_7QStringENS_2Qt13TextElideModeEii");
        g_qfontmetricsf_elided = (qfontmetricsf_elided_fn)dlsym(RTLD_NEXT,
            "_ZNK2QT13QFontMetricsF10elidedTextERKNS_7QStringENS_2Qt13TextElideModeEdi");
        g_qlineedit_setplaceholder = (qlineedit_setplaceholder_fn)dlsym(RTLD_NEXT,
            "_ZN2QT9QLineEdit18setPlaceholderTextERKNS_7QStringE");
        g_qtextedit_setplaceholder = (qtextedit_setplaceholder_fn)dlsym(RTLD_NEXT,
            "_ZN2QT9QTextEdit18setPlaceholderTextERKNS_7QStringE");
        g_qcombo_setitemtext = (qcombobox_setitemtext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT9QComboBox11setItemTextEiRKNS_7QStringE");
        g_qsystray_settooltip = (qsystray_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT15QSystemTrayIcon10setToolTipERKNS_7QStringE");
        g_qwizard_settitle = (qwizard_settitle_fn)dlsym(RTLD_NEXT,
            "_ZN2QT11QWizardPage8setTitleERKNS_7QStringE");
        g_qact_seticontext = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QAction11setIconTextERKNS_7QStringE");
        g_qact_setstatustip = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QAction12setStatusTipERKNS_7QStringE");
        g_qact_setwhatsthis = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QAction12setWhatsThisERKNS_7QStringE");
        g_qwidget_setstatustip = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QWidget12setStatusTipERKNS_7QStringE");
        g_qwidget_setwhatsthis = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QWidget12setWhatsThisERKNS_7QStringE");
        g_qplaintext_setplaceholder = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT14QPlainTextEdit18setPlaceholderTextERKNS_7QStringE");
        g_qcommandlink_setdescription = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT18QCommandLinkButton14setDescriptionERKNS_7QStringE");
        g_qtabbar_settabtext = (qtabwidget_settabtext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QTabBar10setTabTextEiRKNS_7QStringE");
        g_qtabbar_settabtooltip = (qtabwidget_settabtext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QTabBar13setTabToolTipEiRKNS_7QStringE");
        g_qtabbar_settabwhatsthis = (qtabwidget_settabtext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT7QTabBar15setTabWhatsThisEiRKNS_7QStringE");
        g_qtoolbox_setitemtext = (qtabwidget_settabtext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT8QToolBox11setItemTextEiRKNS_7QStringE");
        g_qtoolbox_setitemtooltip = (qtabwidget_settabtext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT8QToolBox14setItemToolTipEiRKNS_7QStringE");
        g_qfiledialog_setlabeltext = (qtabwidget_settabtext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT11QFileDialog12setLabelTextENS0_11DialogLabelERKNS_7QStringE");
        g_qinputdialog_setlabeltext = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT12QInputDialog12setLabelTextERKNS_7QStringE");
        g_qinputdialog_setoktext = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT12QInputDialog15setOkButtonTextERKNS_7QStringE");
        g_qinputdialog_setcanceltext = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT12QInputDialog19setCancelButtonTextERKNS_7QStringE");
        g_qmsgbox_setinformative = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT11QMessageBox18setInformativeTextERKNS_7QStringE");
        g_qmsgbox_setdetailed = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT11QMessageBox15setDetailedTextERKNS_7QStringE");
        g_qmsgbox_setwindowtitle = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT11QMessageBox14setWindowTitleERKNS_7QStringE");
        g_qmsgbox_setbuttontext = (qtabwidget_settabtext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT11QMessageBox13setButtonTextEiRKNS_7QStringE");
        g_qprogress_setlabeltext = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT15QProgressDialog12setLabelTextERKNS_7QStringE");
        g_qprogress_setcanceltext = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT15QProgressDialog19setCancelButtonTextERKNS_7QStringE");
        g_qwizard_setsubtitle = (qwidget_settooltip_fn)dlsym(RTLD_NEXT,
            "_ZN2QT11QWizardPage11setSubTitleERKNS_7QStringE");
        g_qwizard_setbuttontext = (qtabwidget_settabtext_fn)dlsym(RTLD_NEXT,
            "_ZN2QT11QWizardPage13setButtonTextENS_7QWizard12WizardButtonERKNS_7QStringE");
        g_qstatusbar_showmessage = (qstatusbar_showmessage_fn)dlsym(RTLD_NEXT,
            "_ZN2QT10QStatusBar11showMessageERKNS_7QStringEi");

        if (!g_qstring_utf16_ctor)
            fprintf(stderr, "[ida_lang_hook] WARNING: Qt6 QString constructor not found\n");
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// 高层 UI 挂钩（控件setter + 菜单绘制层）
// ═══════════════════════════════════════════════════════════════════════════
// 缓存已翻译构建的QString，避免内存泄漏以及重复分配
static std::mutex g_qstring_cache_mutex;
static std::unordered_map<std::string, QString> g_qstring_cache;

static const QString* translated_for_display(const QString* str) {
    if (!str || !str->ptr || str->size <= 0) return str;

    std::string utf8_text = qstring_to_utf8(str);
    if (utf8_text.empty()) return str;
    auto& std_tr = get_trans();
    auto it = std_tr.find(utf8_text);
    if (it == std_tr.end()) {
        record_missing(utf8_text.c_str());
        return str;
    }
    if (it->second == utf8_text) return str;

    std::lock_guard<std::mutex> lock(g_qstring_cache_mutex);
    auto cached = g_qstring_cache.find(utf8_text);
    if (cached == g_qstring_cache.end()) {
        QString translated;
        if (fill_qstring(&translated, it->second.c_str()))
            cached = g_qstring_cache.emplace(utf8_text, translated).first;
    }
    return cached == g_qstring_cache.end() ? str : &cached->second;
}

template<typename OriginalFunc>
static void ui_hook_template(OriginalFunc& orig_fn, void* self, const QString* str) {
    resolve_qt_symbols();
    if (!orig_fn) return;
    if (!str || !str->ptr || str->size <= 0) {
        orig_fn(self, str);
        return;
    }
    
    std::string utf8_text = qstring_to_utf8(str);
    if (!utf8_text.empty()) {
        auto& std_tr = get_trans();
        auto it = std_tr.find(utf8_text);
        if (it != std_tr.end()) {
            if (it->second == utf8_text) {
                orig_fn(self, str);
                return;
            }
            const QString* translated_ptr = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_qstring_cache_mutex);
                auto cached = g_qstring_cache.find(utf8_text);
                if (cached == g_qstring_cache.end()) {
                    QString translated;
                    // 保留在缓存中，确保Qt控件复制字符串时数据始终有效。
                    if (fill_qstring(&translated, it->second.c_str()))
                        cached = g_qstring_cache.emplace(utf8_text, translated).first;
                }
                if (cached != g_qstring_cache.end())
                    translated_ptr = &cached->second;
            }
            // Qt调用可能再次进入本钩子，不能在持有缓存锁时调用。
            if (translated_ptr) {
                orig_fn(self, translated_ptr);
                return;
            }
        } else record_missing(utf8_text.c_str());
    }
    orig_fn(self, str);
}

template<typename OriginalFunc>
static void ui_hook_template_int(OriginalFunc& orig_fn, void* self, int index, const QString* str) {
    resolve_qt_symbols();
    if (!orig_fn) return;
    if (!str || !str->ptr || str->size <= 0) {
        orig_fn(self, index, str);
        return;
    }
    
    std::string utf8_text = qstring_to_utf8(str);
    if (!utf8_text.empty()) {
        auto& std_tr = get_trans();
        auto it = std_tr.find(utf8_text);
        if (it != std_tr.end()) {
            if (it->second == utf8_text) {
                orig_fn(self, index, str);
                return;
            }
            const QString* translated_ptr = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_qstring_cache_mutex);
                auto cached = g_qstring_cache.find(utf8_text);
                if (cached == g_qstring_cache.end()) {
                    QString translated;
                    if (fill_qstring(&translated, it->second.c_str()))
                        cached = g_qstring_cache.emplace(utf8_text, translated).first;
                }
                if (cached != g_qstring_cache.end())
                    translated_ptr = &cached->second;
            }
            if (translated_ptr) {
                orig_fn(self, index, translated_ptr);
                return;
            }
        } else record_missing(utf8_text.c_str());
    }
    orig_fn(self, index, str);
}

template<typename OriginalFunc>
static void ui_hook_template_string_int(OriginalFunc& orig_fn, void* self,
                                        const QString* str, int value) {
    resolve_qt_symbols();
    if (!orig_fn) return;
    if (!str || !str->ptr || str->size <= 0) {
        orig_fn(self, str, value);
        return;
    }

    std::string utf8_text = qstring_to_utf8(str);
    if (!utf8_text.empty()) {
        auto& std_tr = get_trans();
        auto it = std_tr.find(utf8_text);
        if (it != std_tr.end()) {
            if (it->second == utf8_text) {
                orig_fn(self, str, value);
                return;
            }
            const QString* translated_ptr = nullptr;
            {
                std::lock_guard<std::mutex> lock(g_qstring_cache_mutex);
                auto cached = g_qstring_cache.find(utf8_text);
                if (cached == g_qstring_cache.end()) {
                    QString translated;
                    if (fill_qstring(&translated, it->second.c_str()))
                        cached = g_qstring_cache.emplace(utf8_text, translated).first;
                }
                if (cached != g_qstring_cache.end()) translated_ptr = &cached->second;
            }
            if (translated_ptr) {
                orig_fn(self, translated_ptr, value);
                return;
            }
        } else record_missing(utf8_text.c_str());
    }
    orig_fn(self, str, value);
}

extern "C" void _ZN2QT15QAbstractButton7setTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qbtn_settext, self, str);
}

extern "C" void _ZN2QT6QLabel7setTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qlabel_settext, self, str);
}

extern "C" void _ZN2QT7QWidget14setWindowTitleERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qwidget_setwndtitle, self, str);
}

extern "C" void _ZN2QT7QWidget10setToolTipERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qwidget_settooltip, self, str);
}

extern "C" void _ZN2QT7QAction10setToolTipERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qact_settooltip, self, str);
}

extern "C" void _ZN2QT9QGroupBox8setTitleERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qgrpbox_settitle, self, str);
}

extern "C" void _ZN2QT10QTabWidget10setTabTextEiRKNS_7QStringE(void* self, int index, const QString* str) {
    ui_hook_template_int(g_qtabwdg_settabtext, self, index, str);
}

extern "C" void _ZN2QT11QMessageBox7setTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qmsgbox_settext, self, str);
}

// IDA用QAction/QMenu中保存的英文文本解析"Edit/Comments/..."菜单路径。
// 因此不能在setText/setTitle/addAction阶段替换它们；QPainter收到的是纯显示
// 数据，在这里换成译文不会改变菜单对象的属性或后续路径查找结果。
extern "C" void _ZN2QT8QPainter8drawTextERKNS_5QRectEiRKNS_7QStringEPS1_(
    void* self, const void* rect, int flags, const QString* str, void* bounding_rect) {
    resolve_qt_symbols();
    if (!g_qpainter_drawtext_rect) return;
    g_qpainter_drawtext_rect(
        self, rect, flags, translated_for_display(str), bounding_rect);
}

// 菜单尺寸计算发生在绘制之前。若仍按英文原文测量，较长的中文译文会
// 被挤进英文宽度。字体度量同样使用临时译文，但不回写QAction属性。
extern "C" int _ZNK2QT12QFontMetrics17horizontalAdvanceERKNS_7QStringEi(
    const void* self, const QString* str, int length) {
    resolve_qt_symbols();
    if (!g_qfontmetrics_advance) return 0;
    const QString* display = translated_for_display(str);
    int display_length = display != str && length >= 0 ? (int)display->size : length;
    return g_qfontmetrics_advance(self, display, display_length);
}

extern "C" QRect _ZNK2QT12QFontMetrics12boundingRectERKNS_7QStringE(
    const void* self, const QString* str) {
    resolve_qt_symbols();
    if (!g_qfontmetrics_bounding) return QRect{0, 0, -1, -1};
    return g_qfontmetrics_bounding(self, translated_for_display(str));
}

extern "C" QRect _ZNK2QT12QFontMetrics12boundingRectERKNS_5QRectEiRKNS_7QStringEiPi(
    const void* self, const QRect* rect, int flags, const QString* str,
    int tab_stops, int* tab_array) {
    resolve_qt_symbols();
    if (!g_qfontmetrics_bounding_rect) return QRect{0, 0, -1, -1};
    return g_qfontmetrics_bounding_rect(
        self, rect, flags, translated_for_display(str), tab_stops, tab_array);
}

extern "C" QSize _ZNK2QT12QFontMetrics4sizeEiRKNS_7QStringEiPi(
    const void* self, int flags, const QString* str, int tab_stops,
    int* tab_array) {
    resolve_qt_symbols();
    if (!g_qfontmetrics_size) return QSize{-1, -1};
    return g_qfontmetrics_size(
        self, flags, translated_for_display(str), tab_stops, tab_array);
}

// elidedText会生成一个全新的、带省略号的派生字符串。必须在它处理完整
// 原文之前替换为译文；若等到drawText阶段，词典已无法匹配派生结果。
extern "C" void _ZNK2QT12QFontMetrics10elidedTextERKNS_7QStringENS_2Qt13TextElideModeEii(
    QString* out, const void* self, const QString* str, int mode,
    int width, int flags) {
    resolve_qt_symbols();
    if (!g_qfontmetrics_elided) {
        *out = QString{nullptr, nullptr, 0};
        return;
    }
    g_qfontmetrics_elided(
        out, self, translated_for_display(str), mode, width, flags);
}

extern "C" void _ZNK2QT13QFontMetricsF10elidedTextERKNS_7QStringENS_2Qt13TextElideModeEdi(
    QString* out, const void* self, const QString* str, int mode,
    double width, int flags) {
    resolve_qt_symbols();
    if (!g_qfontmetricsf_elided) {
        *out = QString{nullptr, nullptr, 0};
        return;
    }
    g_qfontmetricsf_elided(
        out, self, translated_for_display(str), mode, width, flags);
}

extern "C" void _ZN2QT9QLineEdit18setPlaceholderTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qlineedit_setplaceholder, self, str);
}

extern "C" void _ZN2QT9QTextEdit18setPlaceholderTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qtextedit_setplaceholder, self, str);
}

extern "C" void _ZN2QT9QComboBox11setItemTextEiRKNS_7QStringE(void* self, int index, const QString* str) {
    ui_hook_template_int(g_qcombo_setitemtext, self, index, str);
}

extern "C" void _ZN2QT15QSystemTrayIcon10setToolTipERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qsystray_settooltip, self, str);
}

extern "C" void _ZN2QT11QWizardPage8setTitleERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qwizard_settitle, self, str);
}

extern "C" void _ZN2QT7QAction11setIconTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qact_seticontext, self, str);
}
extern "C" void _ZN2QT7QAction12setStatusTipERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qact_setstatustip, self, str);
}
extern "C" void _ZN2QT7QAction12setWhatsThisERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qact_setwhatsthis, self, str);
}
extern "C" void _ZN2QT7QWidget12setStatusTipERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qwidget_setstatustip, self, str);
}
extern "C" void _ZN2QT7QWidget12setWhatsThisERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qwidget_setwhatsthis, self, str);
}
extern "C" void _ZN2QT14QPlainTextEdit18setPlaceholderTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qplaintext_setplaceholder, self, str);
}
extern "C" void _ZN2QT18QCommandLinkButton14setDescriptionERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qcommandlink_setdescription, self, str);
}
extern "C" void _ZN2QT7QTabBar10setTabTextEiRKNS_7QStringE(void* self, int index, const QString* str) {
    ui_hook_template_int(g_qtabbar_settabtext, self, index, str);
}
extern "C" void _ZN2QT7QTabBar13setTabToolTipEiRKNS_7QStringE(void* self, int index, const QString* str) {
    ui_hook_template_int(g_qtabbar_settabtooltip, self, index, str);
}
extern "C" void _ZN2QT7QTabBar15setTabWhatsThisEiRKNS_7QStringE(void* self, int index, const QString* str) {
    ui_hook_template_int(g_qtabbar_settabwhatsthis, self, index, str);
}
extern "C" void _ZN2QT8QToolBox11setItemTextEiRKNS_7QStringE(void* self, int index, const QString* str) {
    ui_hook_template_int(g_qtoolbox_setitemtext, self, index, str);
}
extern "C" void _ZN2QT8QToolBox14setItemToolTipEiRKNS_7QStringE(void* self, int index, const QString* str) {
    ui_hook_template_int(g_qtoolbox_setitemtooltip, self, index, str);
}
extern "C" void _ZN2QT11QFileDialog12setLabelTextENS0_11DialogLabelERKNS_7QStringE(
    void* self, int label, const QString* str) {
    ui_hook_template_int(g_qfiledialog_setlabeltext, self, label, str);
}
extern "C" void _ZN2QT12QInputDialog12setLabelTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qinputdialog_setlabeltext, self, str);
}
extern "C" void _ZN2QT12QInputDialog15setOkButtonTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qinputdialog_setoktext, self, str);
}
extern "C" void _ZN2QT12QInputDialog19setCancelButtonTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qinputdialog_setcanceltext, self, str);
}
extern "C" void _ZN2QT11QMessageBox18setInformativeTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qmsgbox_setinformative, self, str);
}
extern "C" void _ZN2QT11QMessageBox15setDetailedTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qmsgbox_setdetailed, self, str);
}
extern "C" void _ZN2QT11QMessageBox14setWindowTitleERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qmsgbox_setwindowtitle, self, str);
}
extern "C" void _ZN2QT11QMessageBox13setButtonTextEiRKNS_7QStringE(void* self, int button, const QString* str) {
    ui_hook_template_int(g_qmsgbox_setbuttontext, self, button, str);
}
extern "C" void _ZN2QT15QProgressDialog12setLabelTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qprogress_setlabeltext, self, str);
}
extern "C" void _ZN2QT15QProgressDialog19setCancelButtonTextERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qprogress_setcanceltext, self, str);
}
extern "C" void _ZN2QT11QWizardPage11setSubTitleERKNS_7QStringE(void* self, const QString* str) {
    ui_hook_template(g_qwizard_setsubtitle, self, str);
}
extern "C" void _ZN2QT11QWizardPage13setButtonTextENS_7QWizard12WizardButtonERKNS_7QStringE(
    void* self, int button, const QString* str) {
    ui_hook_template_int(g_qwizard_setbuttontext, self, button, str);
}
extern "C" void _ZN2QT10QStatusBar11showMessageERKNS_7QStringEi(
    void* self, const QString* str, int timeout) {
    ui_hook_template_string_int(g_qstatusbar_showmessage, self, str, timeout);
}

// ═══════════════════════════════════════════════════════════════════════════
// 生命周期
// ═══════════════════════════════════════════════════════════════════════════
__attribute__((constructor))
static void on_load() {
    // 预热翻译表（触发文件加载，打印条目数）
    get_trans();
}

__attribute__((destructor))
static void on_unload() {
    if (g_missing.empty()) return;

    const char* out_path = "/tmp/ida_missing_translations.txt";
    std::ofstream f(out_path);
    if (!f.is_open()) {
        fprintf(stderr, "[ida_lang_hook] failed to write missing list\n");
        return;
    }
    // 写成可直接追加到ida_lang.txt的格式，译文留空等待填写
    f << "# IDA未翻译字符串 - 请在右侧填入译文后追加到ida_lang.txt\n";
    for (auto& s : g_missing) {
        // 转义引号和反斜杠
        std::string escaped;
        for (char c : s) {
            if (c == '"')  escaped += "\\\"";
            else if (c == '\\') escaped += "\\\\";
            else if (c == '\n') escaped += "\\n";
            else if (c == '\r') escaped += "\\r";
            else if (c == '\t') escaped += "\\t";
            else escaped += c;
        }
        f << "L\"" << escaped << "\",L\"" << escaped << "\",\n";
    }
    fprintf(stderr, "[ida_lang_hook] %zu missing -> %s\n", g_missing.size(), out_path);
}
