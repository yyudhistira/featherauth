#!/bin/sh
# Off-server backup: encrypts the newest snapshot with age and copies
# the encrypted file with rclone or rsync. Run it from the host cron job after
# the service's daily snapshot (backup.at), for example:
#
#   30 3 * * * AGE_RECIPIENT=age1... CONFIG_DIR=/etc/featherauth /opt/featherauth/backup-offsite.sh rsync backup@vault.example.com:featherauth/
#
# Usage: backup-offsite.sh rclone|rsync <destination>
#   rclone: destination is a remote path, such as remote:featherauth
#   rsync:  destination is a directory path or host:directory, such as
#           backup@host:featherauth/ (a trailing slash is added when missing,
#           so the copy always lands inside the directory)
#
# Environment:
#   AGE_RECIPIENT  the age public key (age1...), required. The private key
#                  stays off the server: this script never reads it and only
#                  encrypts. The service holds no credentials for the
#                  destination; the cron user does (ssh key, rclone config).
#   CONFIG_DIR     the configuration directory (FEATHERAUTH_CONFIG_DIR). When
#                  set, a tar of it is encrypted the same way and copied as its
#                  own file, featherauth-config-YYYYMMDD-HHMM.tar.age (same
#                  stamp as the snapshot). It holds the key files, so it is
#                  never copied in clear: the tar is made in a private
#                  temporary directory that is removed on exit. Unset: only
#                  the snapshot is copied.
#   BACKUP_DIR     where the snapshots are (backup.directory), default
#                  /var/backups/featherauth.
#
# The snapshot copy is named like the snapshot plus .age. To restore, decrypt it
# off the server with the private key (age -d -i <key> -o featherauth.db
# <file>.age), stop the service, copy the result to sqlite.path and start.
# Keeping or deleting old copies at the destination is the operator's job.
# Needs age, tar when CONFIG_DIR is set, and the chosen copy tool.
set -eu
umask 077

usage() {
  echo "usage: AGE_RECIPIENT=age1... $0 rclone|rsync <destination>" >&2
  exit 2
}

[ "$#" -eq 2 ] || usage
tool=$1
dest=$2
case "$tool" in rclone|rsync) ;; *) usage ;; esac
[ -n "$dest" ] || usage
dir=${BACKUP_DIR:-/var/backups/featherauth}

recipient=${AGE_RECIPIENT:-}
case "$recipient" in
  age1?*) ;;
  *) echo "backup-offsite: AGE_RECIPIENT must be an age public key (age1...)" >&2; exit 2 ;;
esac

# The names carry YYYYMMDD-HHMM, so the newest sorts last.
newest=$(ls -1 "$dir" 2>/dev/null | grep -E '^featherauth-[0123456789]{8}-[0123456789]{4}\.db$' | sort | tail -n 1 || true)
if [ -z "$newest" ]; then
  echo "backup-offsite: no snapshot in $dir" >&2
  exit 1
fi

config=${CONFIG_DIR:-}
if [ -n "$config" ] && [ ! -d "$config" ]; then
  echo "backup-offsite: CONFIG_DIR $config is not a directory" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

copy() {
  case "$tool" in
    rclone) rclone copyto "$tmp/$1" "${dest%/}/$1" ;;
    rsync) rsync -t "$tmp/$1" "${dest%/}/" ;;
  esac
  echo "copied $1 to $dest"
}

age -r "$recipient" -o "$tmp/$newest.age" "$dir/$newest"
copy "$newest.age"

if [ -n "$config" ]; then
  stamp=${newest#featherauth-}
  stamp=${stamp%.db}
  name=featherauth-config-$stamp.tar.age
  tar -C "$config" -cf "$tmp/config.tar" .
  age -r "$recipient" -o "$tmp/$name" "$tmp/config.tar"
  rm -f "$tmp/config.tar"
  copy "$name"
fi
