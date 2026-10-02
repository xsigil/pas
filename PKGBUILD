pkgname=pas-git
pkgver=1.0.0.r0.g$(git rev-parse --short HEAD 2>/dev/null || echo "latest")
pkgrel=1
pkgdesc="Zero-metadata, anti-forensic secret store for Wayland & Linux (VCS master/main)"
arch=('x86_64' 'aarch64')
url="https://github.com/xsigil/pas"
license=('MIT')
depends=('gnupg' 'fzf' 'wl-clipboard')
makedepends=('go' 'git')
optdepends=(
  'gawk: for scripts/migrate-legacy.sh legacy store migration'
)
provides=('pas')
conflicts=('pas')
source=("pas::git+$url.git")
sha256sums=('SKIP')

pkgver() {
  cd pas
  git describe --long --tags 2>/dev/null | sed 's/^v//;s/\([^-]*-g\)/r\1/;s/-/./g' || \
  printf "1.0.0.r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
  cd pas
  export CGO_CPPFLAGS="${CPPFLAGS}"
  export CGO_CFLAGS="${CFLAGS}"
  export CGO_CXXFLAGS="${CXXFLAGS}"
  export CGO_LDFLAGS="${LDFLAGS}"
  export GOFLAGS="-buildmode=pie -trimpath -modcacherw"

  go build -trimpath -ldflags="-s -w -X main.version=$pkgver -linkmode=external" -o build/pas src/main.go
}

package() {
  cd pas
  install -Dm755 build/pas "$pkgdir/usr/bin/pas"
  install -Dm755 scripts/migrate-legacy.sh "$pkgdir/usr/share/pas/scripts/migrate-legacy.sh"
  install -Dm644 README.md "$pkgdir/usr/share/doc/pas/README.md"
  install -Dm644 SPEC.md "$pkgdir/usr/share/doc/pas/SPEC.md"

  if [ -f LICENSE ]; then
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  fi
}