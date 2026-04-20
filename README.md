# IDA Pro 9.1.250226 for Arch Linux

IDA Pro 9.1.250226 is a crucial tool for reverse engineering, but installing it on Arch Linux used to be a hassle. The `ida-pro` package on the AUR required you to manually download the installer and place it next to the `PKGBUILD` file, making it impossible to use AUR helpers like `yay` for a fully automated install.

This repository provides a new, automated way to install IDA Pro on Arch Linux using an updated PKGBUILD that fetches the installer for you.

## Prerequisites

- Arch Linux system
- Basic knowledge of using the terminal
- [git](https://git-scm.com/) and [base-devel](https://wiki.archlinux.org/title/Development_tools) packages installed

To install `base-devel` if you haven't already:

```bash
sudo pacman -S --needed base-devel
```

## Installation

```bash
makepkg -sicf
```

## Links

- [aur/ida-pro](https://aur.archlinux.org/packages/ida-pro)
- [hex-rays](https://hex-rays.com/)

## Credits

- [patchouli](https://aur.archlinux.org/account/patchouli/): Original maintainer of the `ida-pro` AUR package
