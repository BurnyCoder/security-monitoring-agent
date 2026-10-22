# Global: inspect distro metadata and package database only. Local: no filesystem traversal or updates.
# Sources: https://manpages.debian.org/unstable/dpkg/dpkg-query.1.en.html and https://www.freedesktop.org/software/systemd/man/latest/os-release.html
cat /etc/os-release # Local: distro identity determines the applicable advisory ecosystem.
printf '\n__SM_KERNEL__\n' # Global: separate OS metadata from kernel evidence.
uname -r # Local: record the actual running kernel, including the WSL suffix.
if command -v dpkg-query >/dev/null 2>&1; then # Local: only use the package manager actually installed.
    printf '__SM_PACKAGES__\n' # Global: begin tab-delimited installed-package evidence.
    dpkg-query -W -f='${db:Status-Status}\t${binary:Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n' || printf '__SM_PACKAGES_ERROR__\n' # Local: source identity/version handles distro packaging accurately.
else # Local: other distros still retain OS/kernel evidence.
    printf '__SM_PACKAGES_UNSUPPORTED__\n' # Global: unsupported cannot be interpreted as no affected packages.
fi # Local: complete one distro inspection without installing tools.
