#!/bin/sh
# Installs whycant:
#
#   curl -fsSL https://muneeb-devp.github.io/whycant/install.sh | sh
#
# Uses the system package manager where it can, so upgrades arrive with the
# rest of the system:
#
#   apt (Debian, Ubuntu, ...)        the signed apt repository
#   dnf, yum, zypper (Fedora, RHEL, openSUSE, ...)  the signed rpm repository
#   apk (Alpine)                     the .apk from the latest release
#   anything else                    the static binary in /usr/local/bin
#                                    (~/.local/bin without root)
#
# Options, passed as "| sh -s -- --binary":
#
#   --binary    install the static binary even if a package manager is available
#   --dry-run   print what would run, without changing anything
#
# Everything runs from main() on the last line, so a partial download does
# nothing.
set -eu

REPO_URL=${WHYCANT_REPO_URL:-https://muneeb-devp.github.io/whycant}
RELEASES_URL=${WHYCANT_RELEASES_URL:-https://github.com/muneeb-devp/whycant/releases}

DRY_RUN=
SUDO=
TMP=

say() { printf 'whycant: %s\n' "$*" >&2; }
die() {
  say "error: $*"
  exit 1
}
have() { command -v "$1" >/dev/null 2>&1; }

# run prints a command and runs it as root.
run() {
  printf '+ %s\n' "$*" >&2
  [ -n "$DRY_RUN" ] && return 0
  $SUDO "$@" </dev/null
}

# write_root writes stdin to a root-owned file.
write_root() {
  if [ -n "$DRY_RUN" ]; then
    printf '+ write %s:\n' "$1" >&2
    sed 's/^/    /' >&2
    return 0
  fi
  printf '+ write %s\n' "$1" >&2
  $SUDO tee "$1" >/dev/null
}

fetch() {
  if have curl; then
    curl -fsSL -o "$2" "$1"
  elif have wget; then
    wget -q -O "$2" "$1"
  else
    die "curl or wget is needed to download whycant"
  fi
}

find_root() {
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=
  elif have sudo; then
    SUDO=sudo
  elif have doas; then
    SUDO=doas
  elif [ -n "$DRY_RUN" ]; then
    SUDO=sudo
  else
    return 1
  fi
}

latest_version() {
  fetch "$REPO_URL/version" "$TMP/version" || die "could not find the latest version at $REPO_URL/version"
  v=$(tr -d ' \n' <"$TMP/version")
  case $v in
    [0-9]*) printf '%s\n' "$v" ;;
    *) die "unexpected version \"$v\" from $REPO_URL/version" ;;
  esac
}

# download_release fetches a release file and checks it against the
# release's checksums.txt.
download_release() {
  version=$1
  file=$2
  base="$RELEASES_URL/download/v$version"
  say "downloading $file"
  fetch "$base/$file" "$TMP/$file" || die "could not download $base/$file"
  fetch "$base/checksums.txt" "$TMP/checksums.txt" || die "could not download $base/checksums.txt"
  grep "  $file\$" "$TMP/checksums.txt" >"$TMP/sum" || die "$file is not in checksums.txt"
  if have sha256sum; then
    (cd "$TMP" && sha256sum -c sum >/dev/null) || die "checksum mismatch for $file"
  elif have shasum; then
    (cd "$TMP" && shasum -a 256 -c sum >/dev/null) || die "checksum mismatch for $file"
  else
    die "sha256sum or shasum is needed to check the download"
  fi
}

install_apt() {
  case $(dpkg --print-architecture) in
    amd64 | arm64 | armhf | riscv64) ;;
    *)
      install_binary
      return
      ;;
  esac
  fetch "$REPO_URL/whycant.gpg" "$TMP/whycant.gpg" || die "could not download the signing key"
  run install -d -m 0755 /etc/apt/keyrings
  run install -m 0644 "$TMP/whycant.gpg" /etc/apt/keyrings/whycant.gpg
  echo "deb [signed-by=/etc/apt/keyrings/whycant.gpg] $REPO_URL/deb stable main" |
    write_root /etc/apt/sources.list.d/whycant.list
  # Refresh only this repository; the rest of the system is left alone.
  run apt-get update -o Dir::Etc::sourcelist=sources.list.d/whycant.list \
    -o Dir::Etc::sourceparts=- -o APT::Get::List-Cleanup=0
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y whycant
  UPGRADE="sudo apt update && sudo apt upgrade"
}

install_rpm() {
  case $(uname -m) in
    x86_64 | aarch64 | armv7l | riscv64) ;;
    *)
      install_binary
      return
      ;;
  esac
  if [ "$1" = zypper ]; then
    run zypper --non-interactive --gpg-auto-import-keys addrepo --refresh "$REPO_URL/rpm/whycant.repo"
    run zypper --non-interactive --gpg-auto-import-keys install whycant
    UPGRADE="sudo zypper update"
    return 0
  fi
  fetch "$REPO_URL/rpm/whycant.repo" "$TMP/whycant.repo" || die "could not download the repository file"
  write_root /etc/yum.repos.d/whycant.repo <"$TMP/whycant.repo"
  run "$1" install -y whycant
  UPGRADE="sudo $1 upgrade"
}

install_apk() {
  case $(uname -m) in
    x86_64) arch=x86_64 ;;
    aarch64) arch=aarch64 ;;
    armv7l) arch=armv7 ;;
    riscv64) arch=riscv64 ;;
    *)
      install_binary
      return
      ;;
  esac
  version=$(latest_version)
  file="whycant_${version}_$arch.apk"
  download_release "$version" "$file"
  run apk add --allow-untrusted "$TMP/$file"
  UPGRADE="rerun this installer"
}

install_binary() {
  case $(uname -m) in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    armv7l) arch=armv7 ;;
    riscv64) arch=riscv64 ;;
    *) die "there is no whycant build for $(uname -m)" ;;
  esac
  version=$(latest_version)
  file="whycant_${version}_linux_$arch.tar.gz"
  download_release "$version" "$file"
  tar -xzf "$TMP/$file" -C "$TMP"

  if find_root; then
    run install -d -m 0755 /usr/local/bin /usr/local/share/man/man1
    run install -m 0755 "$TMP/whycant" /usr/local/bin/whycant
    run install -m 0644 "$TMP/docs/whycant.1" /usr/local/share/man/man1/whycant.1
    BIN=/usr/local/bin/whycant
  else
    say "no root access: installing for this user only"
    SUDO=
    run install -d -m 0755 "$HOME/.local/bin"
    run install -m 0755 "$TMP/whycant" "$HOME/.local/bin/whycant"
    BIN="$HOME/.local/bin/whycant"
    case ":$PATH:" in
      *":$HOME/.local/bin:"*) ;;
      *) say "add $HOME/.local/bin to your PATH to run whycant" ;;
    esac
  fi
  UPGRADE="rerun this installer"
}

main() {
  binary=
  for arg in "$@"; do
    case $arg in
      --binary) binary=1 ;;
      --dry-run) DRY_RUN=1 ;;
      -h | --help)
        sed -n '2,22s/^# \{0,1\}//p' "$0" 2>/dev/null ||
          echo "usage: install.sh [--binary] [--dry-run]"
        return 0
        ;;
      *) die "unknown option $arg (try --binary or --dry-run)" ;;
    esac
  done

  [ "$(uname -s)" = Linux ] || die "whycant only runs on Linux (this is $(uname -s))"
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  BIN=whycant
  UPGRADE=

  if [ -n "$binary" ]; then
    install_binary
  elif have apt-get && have dpkg; then
    find_root || die "installing with apt needs root: rerun as root, or use --binary"
    install_apt
  elif have dnf || have yum || have zypper; then
    find_root || die "installing packages needs root: rerun as root, or use --binary"
    for pm in dnf yum zypper; do
      if have "$pm"; then
        install_rpm "$pm"
        break
      fi
    done
  elif have apk; then
    find_root || die "installing with apk needs root: rerun as root, or use --binary"
    install_apk
  else
    install_binary
  fi

  [ -n "$DRY_RUN" ] && return 0
  say "installed $("$BIN" --version)"
  say "try: whycant read /etc/shadow -u nobody"
  say "to upgrade later: $UPGRADE"
}

main "$@"
