# IDA Pro 9.1.250226 ZH_CN for Arch Linux

IDA Pro 9.1.250226 is a crucial tool for reverse engineering, but installing it on Arch Linux used to be a hassle. The `ida-pro` package on the AUR required you to manually download the installer and place it next to the `PKGBUILD` file, making it impossible to use AUR helpers like `yay` for a fully automated install.

This repository provides a new, automated way to install IDA Pro on Arch Linux using an updated PKGBUILD that fetches the installer for you.

## Localization (汉化说明)

This package includes a custom, safe UI translation hook based on Qt5 `LD_PRELOAD`. Most of the IDA Pro user interface and menus have been translated into Simplified Chinese without modifying the underlying core strings, thereby avoiding crashes.
If you want to customize or add new translations, simply modify the `ida_lang.txt` dictionary file. 
The untranslated strings detected are saved in /tmp/ida_missing_translations.txt.

本项目包含了一个基于 Qt5 `LD_PRELOAD` 的安全 UI 汉化补丁。界面和菜单的大部分内容已安全翻译为简体中文，避免了直接修改底层字符串引发的 IDA 崩溃。
如果需要自定义或补充汉化，可以直接修改 `ida_lang.txt` 字典文件。
运行时检测到的未翻译字符串将会保存在 /tmp/ida_missing_translations.txt 中

## Prerequisites

- Arch Linux system
- [git](https://git-scm.com/), [python](https://archlinux.org/packages/extra/x86_64/python/) and [base-devel](https://wiki.archlinux.org/title/Development_tools) packages installed

To install the prerequisites if you haven't already:

```bash
sudo pacman -S --needed base-devel python git
```

## Installation

```bash
makepkg -sicf
```

## Links

- [aur/ida-pro](https://aur.archlinux.org/packages/ida-pro)
- [fr0stb1rd repo](https://gitlab.com/fr0stb1rd/aur-ida-pro)
- [hex-rays](https://hex-rays.com/)

## Credits

- [patchouli](https://aur.archlinux.org/account/patchouli/): Original maintainer of the `ida-pro` AUR package
- [fr0stb1rd](https://gitlab.com/fr0stb1rd/aur-ida-pro): online source of IDA Pro 9.1.250226