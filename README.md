# IDA Pro 9.4 SP1 (9.4.260915) ZH_CN for Arch Linux

IDA Pro 9.4 SP1 is a crucial tool for reverse engineering, but installing it on Arch Linux used to be a hassle. The `ida-pro` package on the AUR required you to manually download the installer and place it next to the `PKGBUILD` file, making it impossible to perform a fully automated install.

This repository provides a new, automated way to install IDA Pro on Arch Linux using an updated PKGBUILD that fetches the installer for you.

## Localization (汉化说明)

This package includes a custom UI translation hook adapted for the Qt6 runtime bundled with IDA Pro 9.4 SP1. Most of the IDA Pro user interface and menus have been translated into Simplified Chinese without modifying the underlying core strings.
If you want to customize or add new translations, simply modify the `ida_lang.txt` dictionary file.
The untranslated strings detected are saved in `/tmp/ida_missing_translations.txt`.

本项目包含了一个适配 IDA Pro 9.4 SP1 自带 Qt6 运行库的 `LD_PRELOAD` UI 汉化补丁。界面和菜单的大部分内容已安全翻译为简体中文，避免了直接修改底层字符串引发的 IDA 崩溃。
如果需要自定义或补充汉化，可以直接修改 `ida_lang.txt` 字典文件。
运行时检测到的未翻译字符串将会保存在 `/tmp/ida_missing_translations.txt` 中。桌面入口和 `/usr/bin/ida` 命令都会自动加载汉化；如需启动原版界面，可直接运行 `/opt/ida-pro/ida`。

词典按用途分为两个有序区段：`[TRANSLATED]` 保存实际汉化，`[KEEP-ORIGINAL]` 保存有意保留英文的专业术语、品牌、快捷键、格式标识以及 IDA 内部使用的菜单/设置路径。等值映射会阻止这些内容反复出现在缺失日志中。钩子不接管 `QCoreApplication::translate` 或 `QTranslator::translate` 等全局翻译入口；普通控件在最终设置显示文字时翻译，菜单则延迟到 `QPainter::drawText` 绘制阶段翻译，并在 `QFontMetrics` 布局阶段按译文测量宽度。这样 `QAction`/`QMenu` 始终保留 IDA 用于路径解析的英文身份文本，只有屏幕显示和布局使用译文，也不会修改反汇编、数据库或其他底层字符串。

合并一次运行产生的新文案并重新排序：

```bash
python tools/maintain_translations.py --missing /tmp/ida_missing_translations.txt
```

新条目默认进入“保留原文”区；将右侧文本改为中文后，再运行 `python tools/maintain_translations.py` 即可自动移入“已汉化”区。动态路径、地址、版本号以及已经翻译过的中文反馈会自动忽略；形如 `Edit/Comments/Enter` 的内部结构路径会被强制保留原文。`Co&mments`、`Ot&her` 中的 `&` 是 Qt 助记键标记，分别表示 Alt+M、Alt+H；它不是需要显示的普通字符。提交前可运行 `python tools/maintain_translations.py --check` 检查格式与排序。

### 汉化设计与维护注意事项

- **菜单身份与显示必须分离。** IDA 使用 `Edit/Comments/...` 这样的英文路径解析菜单；不要重新 Hook `QAction::setText`、`QMenu::setTitle`、菜单 `addAction` 或全局 Qt 翻译入口，否则 IDA 可能找不到原菜单并创建同名重复项。
- **绘制、布局和省略必须使用同一译文。** 菜单文字在 `QPainter::drawText` 阶段替换，宽度在 `QFontMetrics` 阶段按同一译文计算，`QFontMetrics::elidedText`/`QFontMetricsF::elidedText` 则在生成省略文本前先取得完整译文。只改绘制会造成文字拥挤或裁切；让 Qt 先省略英文则会生成无法匹配词典的派生字符串。增加新的绘制或字体度量重载时，应同步检查整条显示管线。
- **不要翻译结构键。** 带 `/` 的菜单路径、动作标识、动态地址、数据库内容和运行时路径不是 UI 文案；它们应保持等值映射或被过滤。钩子只能改变最终显示和布局，不能改变 IDA 底层字符串。
- **保留 Qt 助记键语义。** 原文中的 `&` 标记下一个助记字符，例如 `Ot&her`。中文通常写成 `其他(&H)`；不要为了排序或去重修改词典左侧原文，也不要把普通名称和助记键名称当作可互换的内部标识。
- **明确记录不翻译内容。** API、ABI、调试器名称、产品名、快捷键和确实不宜汉化的专业术语应以等值映射放入 `[KEEP-ORIGINAL]`，避免每次运行重复进入缺失日志。
- **忽略派生显示文本。** 含有 `…` 的字符串（如 `Database sn… &manager...`）通常是 Qt 根据控件宽度生成的临时结果，不应加入词典；完整原文会在进入省略处理前记录，维护脚本会自动过滤省略结果和明显占位符。

## Prerequisites

- Arch Linux system
- [git](https://git-scm.com/), [python](https://archlinux.org/packages/extra/x86_64/python/) and [base-devel](https://wiki.archlinux.org/title/Development_tools) packages installed

To install the prerequisites if you haven't already:

```bash
sudo pacman -S --needed base-devel python git
```

## Installation

```bash
git clone https://github.com/GodKeawa/IDA-Pro-zh_cn.git
cd IDA-Pro-zh_cn
makepkg -sicf
```

## Links

- [aur/ida-pro](https://aur.archlinux.org/packages/ida-pro)
- [IDA Pro 9.4 SP1 installer](https://archive.org/download/ida94sp1/ida-pro_94_x64linux.run)
- [hex-rays](https://hex-rays.com/)

## Credits

- [patchouli](https://aur.archlinux.org/account/patchouli/): Original maintainer of the `ida-pro` AUR package
- [fr0stb1rd](https://gitlab.com/fr0stb1rd/aur-ida-pro-9-4-sp1.git): IDA Pro installer mirror
