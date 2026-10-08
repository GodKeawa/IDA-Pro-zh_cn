pkgver=9.4.260915
pkgname="ida-pro"
pkgrel=1
pkgdesc="Hex-Rays IDA Pro"
url="https://hex-rays.com/ida-pro"
license=('custom')
makedepends=('fakechroot' 'gcc' 'nodejs')
depends=('libgl'
	'libx11'
	'libxext'
	'libxrender'
	'libxtst'
	'glib2'
	'qt6-base'
	'python'
	'python-rpyc'
	)
options=('!strip')

_installer='ida-pro_94_x64linux.run'
source=("https://archive.org/download/ida94sp1/ida-pro_94_x64linux.run"
		"${pkgname}.desktop"
		"${pkgname}-launcher"
        "keygen.js"
		"ida_hook.cpp"
		"ida_lang.txt")

sha256sums=('84ff9d6e773853df00c0a0f438bd66246b2caeadc7489d4e584e9d7c4c628c7c'
            'a49cfdaccef7ef482bc98346cef50df21134b84e23dafef56e12ffc9dc710500'
            'fcf537f0c1163fb4c1d545c6208a4de48f1844e047789abb892488e45b59a718'
            'cc570f24effc008a4ebd514cc3c4fbb5db05bbdeb7f420b79fdf4ed08a4611e2'
            'f0ae5b6b0b052bd454ed04c1c23b4527728d77095f54dcb9019e6d148ef324aa'
            '57cbac84f893b165a32946c28002ae55a8ec86175683c86c379a882fb98c8ca7')

arch=('x86_64')

package() {
	install -d "${pkgdir}"/opt/${pkgname}
	install -d "${pkgdir}"/usr/bin
	install -d "${pkgdir}"/usr/share/{icons,applications,licenses/${pkgname}}
	install -d "${pkgdir}"/tmp

	# chroot is needed to prevent the installer from creating a single file outside of prefix
	# have to copy the installer due to chroot
	cp "${srcdir}"/${_installer} "${pkgdir}"/
	chmod +x "${pkgdir}"/${_installer}

	# IDA Pro 9.0 SP1 (and newer) installer now tries to copy the .desktop files to $HOME even if you specify a prefix. Very annoying.
	mkdir -p "${pkgdir}${HOME}/.local/share/applications"
	fakechroot chroot "${pkgdir}" /${_installer} --mode unattended --prefix "/opt/${pkgname}"
	rm "${pkgdir}"/${_installer}
	rm -rf "${pkgdir}"/{tmp,home}

	# the installer needlessly makes a lot of files executable
	find "${pkgdir}"/opt/${pkgname} -type f -exec chmod -x {} \;
	chmod +x "${pkgdir}"/opt/${pkgname}/{hv,ida,idapyswitch,idat,lc,lsadm,picture_decoder,upg32}

	# IDA 9.3 and newer ship documentation with overly restrictive modes.
	find "${pkgdir}"/opt/${pkgname}/docs -type d -exec chmod 755 {} \;
	find "${pkgdir}"/opt/${pkgname}/docs -type f -exec chmod 644 {} \;

	rm "${pkgdir}"/opt/${pkgname}/{uninstall*,Uninstall*}

	install -Dm644 "${srcdir}"/${pkgname}.desktop "${pkgdir}"/usr/share/applications/${pkgname}.desktop
	ln -s /opt/${pkgname}/appico.png "${pkgdir}"/usr/share/icons/${pkgname}.png
	ln -s /opt/${pkgname}/license.txt "${pkgdir}"/usr/share/licenses/${pkgname}/LICENSE

	# zh_cn
	g++ -O2 -shared -fPIC -std=c++17 -Wall -Wextra -o "${pkgdir}"/opt/${pkgname}/ida_lang_hook.so "${srcdir}"/ida_hook.cpp -ldl
	install -Dm644 "${srcdir}"/ida_lang.txt "${pkgdir}"/opt/${pkgname}/ida_lang.txt
	install -Dm755 "${srcdir}"/${pkgname}-launcher "${pkgdir}"/usr/bin/ida

    # Patch It
    cp "${srcdir}"/keygen.js "${pkgdir}"/opt/${pkgname}
    cd "${pkgdir}"/opt/${pkgname}
    node "${pkgdir}"/opt/${pkgname}/keygen.js
}
