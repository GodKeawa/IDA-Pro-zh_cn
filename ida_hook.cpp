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
#include <set>
#include <mutex>
#include <limits.h>
#include <unistd.h>

// ═══════════════════════════════════════════════════════════════════════════
// QString ABI (Qt5 x86-64, 从IDA自带libQt5Core反汇编确认)
//
// 内存布局:
//   +0x00  ref              (int)
//   +0x04  size             (int)       字符数（不含null）
//   +0x08  alloc            (unsigned)
//   +0x0C  capacityReserved (unsigned)
//   +0x10  offset           (ptrdiff_t) data指针 = (char*)d + d->offset
//
// 调用约定: translate系列函数使用sret，rdi为隐藏返回值指针，
//           真正的参数从rsi开始
// ═══════════════════════════════════════════════════════════════════════════
struct QStringData {
    int       ref;
    int       size;
    unsigned  alloc;
    unsigned  capacityReserved;
    ptrdiff_t offset;
};

struct QString {
    QStringData* d;
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

static void record_missing(const char* sourceText) {
    if (!sourceText || sourceText[0] == '\0') return;
    // 过滤纯空白和单字符（太多噪音）
    if (strlen(sourceText) <= 1) return;
    std::lock_guard<std::mutex> lock(g_missing_mutex);
    g_missing.insert(sourceText);
}

// ═══════════════════════════════════════════════════════════════════════════
// QString 构造工具
// ═══════════════════════════════════════════════════════════════════════════
static QStringData* get_shared_null() {
    static QStringData* sn = nullptr;
    if (!sn)
        sn = (QStringData*)dlsym(RTLD_DEFAULT,
                "_ZN2QT10QArrayData11shared_nullE");
    return sn;
}

static void fill_qstring(QString* out, const char* utf8) {
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
    int nchars = (int)j;

    // 分配: QStringData header + UTF-16数据 + null终止符
    // 使用系统malloc（与IDA的Qt内部allocate一致，都调用malloc）
    size_t header_sz = sizeof(QStringData);
    size_t data_sz   = (nchars + 1) * sizeof(uint16_t);
    QStringData* d   = (QStringData*)malloc(header_sz + data_sz);
    if (!d) {
        out->d = get_shared_null();
        return;
    }

    d->ref              = 1;
    d->size             = nchars;
    d->alloc            = (unsigned)nchars;
    d->capacityReserved = 0;
    d->offset           = (ptrdiff_t)header_sz;

    uint16_t* data_ptr = (uint16_t*)((char*)d + header_sz);
    memcpy(data_ptr, tmp, data_sz);

    out->d = d;
}

// ═══════════════════════════════════════════════════════════════════════════
// 原始函数指针（sret调用约定）
// ═══════════════════════════════════════════════════════════════════════════
typedef void (*qapp_tr_fn)(QString*, const char*, const char*, const char*, int);
typedef void (*qtrans_fn) (QString*, void*, const char*, const char*, const char*, int);

static qapp_tr_fn g_qapp_tr = nullptr;
static qtrans_fn  g_qtrans  = nullptr;

// ═══════════════════════════════════════════════════════════════════════════
// Hook 1: QT::QCoreApplication::translate
// ═══════════════════════════════════════════════════════════════════════════
extern "C"
void _ZN2QT16QCoreApplication9translateEPKcS2_S2_i(
    QString*    __ret,
    const char* context,
    const char* sourceText,
    const char* disambiguation,
    int         n)
{
    if (sourceText) {
        auto& m = get_trans();
        auto  it = m.find(sourceText);
        if (it != m.end()) {
            fill_qstring(__ret, it->second.c_str());
            return;
        }
        record_missing(sourceText);
    }
    if (g_qapp_tr) {
        g_qapp_tr(__ret, context, sourceText, disambiguation, n);
        return;
    }
    __ret->d = get_shared_null();
}

// ═══════════════════════════════════════════════════════════════════════════
// Hook 2: QT::QTranslator::translate (const成员函数，this在sret之后)
// ═══════════════════════════════════════════════════════════════════════════
extern "C"
void _ZNK2QT11QTranslator9translateEPKcS2_S2_i(
    QString*    __ret,
    void*       self,
    const char* context,
    const char* sourceText,
    const char* disambiguation,
    int         n)
{
    if (sourceText) {
        auto& m = get_trans();
        auto  it = m.find(sourceText);
        if (it != m.end()) {
            fill_qstring(__ret, it->second.c_str());
            return;
        }
        record_missing(sourceText);
    }
    if (g_qtrans) {
        g_qtrans(__ret, self, context, sourceText, disambiguation, n);
        return;
    }
    __ret->d = get_shared_null();
}

// ═══════════════════════════════════════════════════════════════════════════
// 生命周期
// ═══════════════════════════════════════════════════════════════════════════
__attribute__((constructor))
static void on_load() {
    g_qapp_tr = (qapp_tr_fn)dlsym(RTLD_NEXT,
        "_ZN2QT16QCoreApplication9translateEPKcS2_S2_i");
    g_qtrans  = (qtrans_fn)dlsym(RTLD_NEXT,
        "_ZNK2QT11QTranslator9translateEPKcS2_S2_i");

    if (!g_qapp_tr) fprintf(stderr, "[ida_lang_hook] WARNING: qapp_tr not found\n");
    if (!g_qtrans)  fprintf(stderr, "[ida_lang_hook] WARNING: qtrans not found\n");

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
            else escaped += c;
        }
        f << "L\"" << escaped << "\",L\"" << escaped << "\",\n";
    }
    fprintf(stderr, "[ida_lang_hook] %zu missing -> %s\n", g_missing.size(), out_path);
}
