# -*- shell-script -*-
# Maintainer: Eric Schulte <schulte.eric@gmail.com>
pkgname=ddisasm-git
_srcdir=ddisasm_pkg
pkgver=r269.28f20d1
pkgrel=1
pkgdesc="A fast disassembler producing resulting assembly code which can be reassembled."
url="https://github..com/grammatech/ddisasm"
arch=('i686' 'x86_64')
license=('GPL3')
depends=()
makedepends=('git' 'pandoc' 'souffle-git' 'cmake')
provides=('ddisasm')
source=("${_srcdir}::git+https://github.com/grammatech/ddisasm")
sha256sums=('SKIP')

pkgver() {
  cd "$_srcdir"
  printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

# prepare() { }

build() {
  cd $_srcdir
  make
}

package() {
  cd "$_srcdir"
  make DESTDIR="$pkgdir/usr/" install
}

# vim: ts=2 sw=2 et:
