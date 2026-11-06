#!/bin/bash
# Run as root inside a private mount namespace on Debian.
set -euo pipefail
[ "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ] || exit 2
repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
mount --make-rprivate /
mkdir -p "$work"/{pam,profiles,cache,debconf,dpkg,opt}
cp -a /etc/pam.d/. "$work/pam/"
cp -a /usr/share/pam-configs/. "$work/profiles/"
cp -a /var/lib/pam/. "$work/cache/"
cp -a /var/cache/debconf/. "$work/debconf/"
touch "$work/dpkg/status"
mount --bind "$work/pam" /etc/pam.d
mount --bind "$work/profiles" /usr/share/pam-configs
mount --bind "$work/cache" /var/lib/pam
mount --bind "$work/debconf" /var/cache/debconf
mount --bind "$work/dpkg" /var/lib/dpkg
mount --bind "$work/opt" /opt
mkdir -p /opt/vyatta/share/pam-configs
cp "$repo"/usr/share/pam-configs/vyatta-{unix,password} /opt/vyatta/share/pam-configs/
# Existing local profiles are not package-owned and cannot be overwritten.
printf 'Name: Site policy\n' > /usr/share/pam-configs/vyatta-password
if DEBIAN_FRONTEND=noninteractive sh "$repo/debian/vyatta-password-renewal.postinst" configure; then
    echo 'configure overwrote a local renewal profile' >&2
    exit 1
fi
grep -qx 'Name: Site policy' /usr/share/pam-configs/vyatta-password
rm /usr/share/pam-configs/vyatta-password
sed -i '/# here are the per-package modules/a password optional pam_permit.so' /etc/pam.d/common-password
cp /etc/pam.d/common-password "$work/expected"
# A modified effective stack must be retained during configure and remove.
DEBIAN_FRONTEND=noninteractive sh "$repo/debian/vyatta-password-renewal.postinst" configure || true
cmp "$work/expected" /etc/pam.d/common-password
DEBIAN_FRONTEND=noninteractive sh "$repo/debian/vyatta-password-renewal.prerm" remove || true
cmp "$work/expected" /etc/pam.d/common-password

# Refuse removal while an edited effective stack still loads the module.
cp "$work/cache/password" /dev/null
sed -i '/password optional pam_permit.so/d' /etc/pam.d/common-password
DEBIAN_FRONTEND=noninteractive sh "$repo/debian/vyatta-password-renewal.postinst" configure
grep -q pam_vyatta_passwd.so /etc/pam.d/common-password
sed -i '/# here are the per-package modules/a password optional pam_permit.so' /etc/pam.d/common-password
if DEBIAN_FRONTEND=noninteractive sh "$repo/debian/vyatta-password-renewal.prerm" remove; then
    echo 'removed active renewal profile from edited stack' >&2
    exit 1
fi
test -f /usr/share/pam-configs/vyatta-password
grep -q pam_vyatta_passwd.so /etc/pam.d/common-password

# Direct site references must prevent removal of the owned PAM module.
sed -i '/password optional pam_permit.so/d' /etc/pam.d/common-password
printf 'password required pam_vyatta_passwd.so\n' > /etc/pam.d/site-custom
if DEBIAN_FRONTEND=noninteractive sh "$repo/debian/vyatta-password-renewal.prerm" remove; then
    echo 'removed a module directly referenced by a site service' >&2
    exit 1
fi
test -f /usr/share/pam-configs/vyatta-password
rm /etc/pam.d/site-custom
# Bind a private pam.conf before checking the traditional service-prefixed form.
printf 'site password required pam_vyatta_passwd.so\n' > "$work/pam.conf"
if [ -e /etc/pam.conf ]; then
    mount --bind "$work/pam.conf" /etc/pam.conf
    if DEBIAN_FRONTEND=noninteractive sh "$repo/debian/vyatta-password-renewal.prerm" remove; then
        echo 'removed a module referenced by pam.conf' >&2
        exit 1
    fi
fi
