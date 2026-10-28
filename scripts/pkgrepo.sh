#!/bin/sh
# Builds the signed apt and dnf repositories served from GitHub Pages.
#
#   scripts/pkgrepo.sh PACKAGES_DIR SITE_DIR
#
# Adds the .deb and .rpm files in PACKAGES_DIR to the site in SITE_DIR (the
# previous gh-pages content, or an empty directory), keeps the newest $KEEP
# versions, and regenerates and signs the indexes. Needs GNU coreutils,
# apt-ftparchive, createrepo_c, rpmsign and gpg with exactly one secret key.
set -eu
pkgs=$1
site=$2
keep=${KEEP:-5}
base=${BASE_URL:-https://muneeb-devp.github.io/whycant}
key=$(gpg --batch --list-secret-keys --with-colons | awk -F: '/^fpr/ { print $10; exit }')

mkdir -p "$site/deb/pool/main" "$site/rpm"
for f in "$pkgs"/*.rpm; do
  # Debian's rpm defaults to gpg2, which Debian does not ship.
  rpmsign --define "__gpg $(command -v gpg)" --define "_gpg_name $key" --addsign "$f" >/dev/null
done
cp "$pkgs"/*.deb "$site/deb/pool/main/"
cp "$pkgs"/*.rpm "$site/rpm/"

# Keep the newest versions only: Pages sites are limited to 1 GB.
ls "$site/deb/pool/main" | sed -n 's/^whycant_\(.*\)_[^_]*\.deb$/\1/p' | sort -uV | head -n "-$keep" |
  while read -r v; do
    rm -f "$site/deb/pool/main/whycant_${v}_"*.deb "$site/rpm/whycant-${v}-"*.rpm
  done

# apt: one "stable" suite, one component, an index per architecture.
(
  cd "$site/deb"
  rm -rf dists
  archs="amd64 arm64 armhf riscv64"
  for arch in $archs; do
    d=dists/stable/main/binary-$arch
    mkdir -p "$d"
    apt-ftparchive --arch "$arch" packages pool/main >"$d/Packages"
    gzip -9kn "$d/Packages"
  done
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=whycant \
    -o APT::FTPArchive::Release::Label=whycant \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o "APT::FTPArchive::Release::Architectures=$archs" \
    -o APT::FTPArchive::Release::Components=main \
    -o "APT::FTPArchive::Release::Description=whycant packages" \
    release dists/stable >Release.tmp
  mv Release.tmp dists/stable/Release
  gpg --batch --yes --local-user "$key" --clearsign -o dists/stable/InRelease dists/stable/Release
  gpg --batch --yes --local-user "$key" --armor --detach-sign -o dists/stable/Release.gpg dists/stable/Release
)

# dnf: every architecture in one directory; dnf picks the matching one.
rm -rf "$site/rpm/repodata"
createrepo_c --quiet "$site/rpm"
gpg --batch --yes --local-user "$key" --armor --detach-sign "$site/rpm/repodata/repomd.xml"
cat >"$site/rpm/whycant.repo" <<EOF
[whycant]
name=whycant
baseurl=$base/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$base/whycant.asc
EOF

gpg --batch --yes --export "$key" >"$site/whycant.gpg"
gpg --batch --yes --armor --export "$key" >"$site/whycant.asc"
touch "$site/.nojekyll"
cat >"$site/index.html" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>whycant packages</title>
<p>Package repositories for <a href="https://github.com/muneeb-devp/whycant">whycant</a>.
Install instructions are in the <a href="https://github.com/muneeb-devp/whycant#install">README</a>.</p>
EOF
