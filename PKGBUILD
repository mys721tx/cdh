# Maintainer: Yishen Miao <mys721tx@gmail.com>
# Packager: Yishen Miao <mys721tx@gmail.com>
pkgname=cdh-git
pkgver=$(make version)
pkgrel=1
pkgdesc="CertBot DANE hook"
arch=('i686' 'x86_64' 'armv7h' 'armv6h' 'aarch64')
url="https://github.com/mys721tx/cdh"
license=('GPL')
depends=(
  'git'
)
makedepends=(
  'go'
)

build() {
  make VERSION=$pkgver DESTDIR="$pkgdir" PREFIX=/usr -C "$startdir"
}

package() {
  make VERSION=$pkgver DESTDIR="$pkgdir" PREFIX=/usr -C "$startdir" install
}
