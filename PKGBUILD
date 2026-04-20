# NOT compatible with AUR helpers!

pkgver=9.1.0
pkgname="ida-pro"
pkgrel=1
pkgdesc="Hex-Rays IDA Pro"
url="https://www.hex-rays.com/products/ida/${pkgver}/index.shtml"
license=('custom')
makedepends=('fakechroot' 'gcc')
depends=('libgl'
	'libx11'
	'libxext'
	'libxrender'
	'glib2'
	'qt5-base'
	'python'
	'python-rpyc'
	)
options=('!strip')

_installer='ida-pro_91_x64linux.run'
# online source by fr0stb1rd
source=("https://archive.org/download/ida-pro_91_x64linux/ida-pro_91_x64linux.run"
		"${pkgname}.desktop"
		"${pkgname}-teams.desktop"
        "keygen3.py"
		"ida_hook.cpp"
		"ida_lang.txt")

sha256sums=('8ff08022be3a0ef693a9e3ea01010d1356b26cfdcbbe7fdd68d01b3c9700f9e2'
            '3e6970b1dc768c0a15a974929ec72338068e600253f52bd39cfaf215236b081d'
            '437fc36a8edd8dd6adadd773dd777966797640d93f499892bdd1217afaf1b636'
            'e778bfca87a658bcb59ed921deb2a1e61370ed5fab514f478ba1d7e0cd308d2a'
			'aed88f8cf2198fc5a730dba35e81bf061e07845673f875a17f44954c56c42f82'
			'd12e5ae5c83382c14f3cc25abb92d50e7b6a9fef684808c5c3a58ae22668da15')

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
	mkdir -p $pkgdir/$HOME/.local/share/applications
	fakechroot chroot "${pkgdir}" /${_installer} --mode unattended --prefix "/opt/${pkgname}"
	rm "${pkgdir}"/${_installer}
	rm -Rf "${pkgdir}"/{tmp,home}

	# the installer needlessly makes a lot of files executable
	find "${pkgdir}"/opt/${pkgname} -type f -exec chmod -x {} \;
	chmod +x "${pkgdir}"/opt/${pkgname}/{assistant,hv,hvui,ida,idapyswitch,idat,picture_decoder,qwingraph,upg32}

	rm "${pkgdir}"/opt/${pkgname}/{uninstall*,Uninstall*}

	install "${srcdir}"/${pkgname}*.desktop "${pkgdir}"/usr/share/applications
	ln -s /opt/${pkgname}/appico.png "${pkgdir}"/usr/share/icons/${pkgname}.png
	ln -s /opt/${pkgname}/hvui.png "${pkgdir}"/usr/share/icons/${pkgname}-teams.png
	ln -s /opt/${pkgname}/license.txt "${pkgdir}"/usr/share/licenses/${pkgname}/LICENSE
	ln -s /opt/${pkgname}/ida "${pkgdir}"/usr/bin/ida

	# zh_cn
	g++ -O2 -shared -fPIC -std=c++17 -o "${pkgdir}"/opt/${pkgname}/ida_lang_hook.so "${srcdir}"/ida_hook.cpp -ldl
	install -Dm644 "${srcdir}"/ida_lang.txt "${pkgdir}"/opt/${pkgname}/ida_lang.txt

    # Patch It
    cp "${srcdir}"/keygen3.py "${pkgdir}"/opt/${pkgname}
    python "${pkgdir}"/opt/${pkgname}/keygen3.py
    rm "${pkgdir}"/opt/${pkgname}/{libida.so,libida32.so}
    mv "${pkgdir}"/opt/${pkgname}/libida.so.patched "${pkgdir}"/opt/${pkgname}/libida.so
    mv "${pkgdir}"/opt/${pkgname}/libida32.so.patched "${pkgdir}"/opt/${pkgname}/libida32.so
}
