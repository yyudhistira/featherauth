#!/bin/sh
# CI check of the off-server backup script. Needs docker; age, rsync,
# rclone and sqlite3 run in a throwaway Alpine container (apk needs network).
# Run from the repository root: deploy/ops/check-offsite.sh
# OFFSITE_SCRIPT is a test hook: it names another copy of the script, to check
# that the leak and slash checks fail on a script that leaks or lacks the fix.
#
# The Alpine image is pinned by digest, but the apk packages are not pinned:
# Alpine keeps only the newest build of each package per release, so a pinned
# version would disappear and break the job.
#
# Flow: a service image with one imported user takes a snapshot; the script
# encrypts the newest snapshot and copies it with rsync and with rclone, holding
# only the public key; the copy must not be a readable SQLite file; with the
# private key it decrypts to the snapshot; the decrypted file is restored on a
# fresh data directory and a service started on it is ready, knows the user and
# answers discovery and the JWKS. The config directory is copied encrypted too.
# A real social login on the restored service is left to the release
# check (docs/RELEASING.md).
set -eu

alpine_img=alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
img=featherauth-ci-offsite:latest
tools=featherauth-ci-offsite-tools:latest
svc=featherauth-ci-offsite-svc
script=${OFFSITE_SCRIPT:-deploy/ops/backup-offsite.sh}
email=offsite-fixture@example.com
tmp=$(mktemp -d)
hostuser="$(id -u):$(id -g)"
cleanup() {
  docker rm -f "$svc" >/dev/null 2>&1 || true
  docker rmi "$img" "$tools" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

docker build -q -f deploy/Dockerfile -t "$img" . >/dev/null
printf 'FROM %s\nRUN apk add --no-cache age rsync rclone sqlite\n' "$alpine_img" | docker build -q -t "$tools" - >/dev/null

# tool runs a command in the tools container, with the given extra mounts. It
# runs as the host user, so that what it writes to a mount is owned by the host
# user on Linux (bind mounts keep owners there) and can be changed and removed
# by this script and its cleanup.
tool() { docker run --rm --user "$hostuser" "$@"; }

mkdir -p "$tmp/data" "$tmp/bk" "$tmp/priv" "$tmp/rsync" "$tmp/rclone" "$tmp/restore" "$tmp/out"

# Configuration with fixture keys (generated here, never real), as check-image.sh.
gen="docker run --rm --user $hostuser --entrypoint /featherauth -v $tmp:/cfg $img"
$gen config init /cfg/c >/dev/null
sed -i.bak 's#^public_url:.*#public_url: http://localhost:8080#; s#^require_https:.*#require_https: false#' "$tmp/c/server.yaml"
# The chmod below makes the fixture files readable by other users, which the
# default strict_permissions refuses; the tools here run as the host user, and
# the default is tested in config and cmd (see check-image.sh).
sed -i.bak 's#^strict_permissions:.*#strict_permissions: false#' "$tmp/c/server.yaml"
$gen keys generate --type rsa /cfg/c/secrets/example/signing-2026-10.pem >/dev/null
$gen keys generate --type ec /cfg/c/secrets/example/apple_key.p8 >/dev/null
$gen keys generate --type encryption /cfg/c/secrets/encryption_key >/dev/null
echo fixture-client-secret >"$tmp/c/secrets/example/client_secret"
cat >"$tmp/users.json" <<JSON
[{"email": "$email", "email_verified": true, "name": "Offsite Fixture", "disabled": false,
  "identities": [{"provider": "google", "subject": "offsite-fixture-subject"}]}]
JSON

# A user in the database, then one snapshot, as the host user so the files can be changed and removed here.
cli="docker run --rm --user $hostuser --entrypoint /featherauth -e FEATHERAUTH_CONFIG_DIR=/etc/featherauth \
  -v $tmp/c:/etc/featherauth:ro -v $tmp/data:/var/lib/featherauth -v $tmp/bk:/var/backups/featherauth -v $tmp/users.json:/users.json:ro $img"
$cli import /users.json --realm example >/dev/null || fail "import"
snap=$($cli backup | sed -n 's#^wrote /var/backups/featherauth/##p')
case "$snap" in featherauth-????????-????.db) ;; *) fail "unexpected snapshot name '$snap'" ;; esac
# An older snapshot, which the script must not pick.
echo old >"$tmp/bk/featherauth-20200101-0000.db"
chmod -R a+rX "$tmp"

# The key pair is made apart from the server's files; only the public key goes on.
tool -v "$tmp/priv:/priv" "$tools" sh -c 'age-keygen -o /priv/key.txt 2>/dev/null; age-keygen -y /priv/key.txt >/priv/pub.txt; age-keygen -o /priv/other.txt 2>/dev/null'
pub=$(cat "$tmp/priv/pub.txt")
case "$pub" in age1*) ;; *) fail "no public key" ;; esac

# Run the script with the public key only: the private key is not mounted.
# $1 is the tool, $2 the destination; the output goes to $tmp/out/$1.log.
run_script() {
  docker run --rm --user "$hostuser" -e "AGE_RECIPIENT=$pub" -e BACKUP_DIR=/bk -e CONFIG_DIR=/etc/featherauth \
    -v "$PWD/$script:/backup-offsite.sh:ro" -v "$tmp/c:/etc/featherauth:ro" \
    -v "$tmp/bk:/bk:ro" -v "$tmp/$1:/dest" "$tools" sh /backup-offsite.sh "$1" "$2" >"$tmp/out/$1.log" 2>&1
}
run_script rsync /dest/ || { cat "$tmp/out/rsync.log"; fail "rsync copy"; }
run_script rclone /dest || { cat "$tmp/out/rclone.log"; fail "rclone copy"; }
# rsync with a destination directory given without a trailing slash: the copy
# goes inside it, never to a file of that name.
run_script rsync /dest/noslash || { cat "$tmp/out/rsync.log"; fail "rsync copy to a destination without a slash"; }
[ -f "$tmp/rsync/noslash/$snap.age" ] || fail "rsync destination without a slash did not get a directory holding the copy"
cfgname=featherauth-config-${snap#featherauth-}
cfgname=${cfgname%.db}.tar.age
[ -f "$tmp/rsync/noslash/$cfgname" ] || fail "rsync destination without a slash lacks the config copy"
rm -r "$tmp/rsync/noslash"
# Re-run to the plain destinations, so their output logs are the final ones.
run_script rsync /dest/ || fail "rsync copy"

# The script's output holds neither snapshot content nor the fixture secrets.
for d in rsync rclone; do
  grep -qF "$email" "$tmp/out/$d.log" && fail "$d output holds the fixture email"
  grep -qF fixture-client-secret "$tmp/out/$d.log" && fail "$d output holds a fixture secret"
  grep -qF "SQLite format 3" "$tmp/out/$d.log" && fail "$d output holds snapshot content"
  grep -qF "$snap.age" "$tmp/out/$d.log" || fail "control: $d output does not name the copy, so the output check proves nothing"
done

# Usage errors and a missing snapshot.
if docker run --rm -e "AGE_RECIPIENT=$pub" -v "$PWD/deploy/ops/backup-offsite.sh:/b.sh:ro" "$tools" sh /b.sh rsync /dest >/dev/null 2>&1; then
  fail "no snapshot directory did not fail"
fi
if docker run --rm -v "$PWD/deploy/ops/backup-offsite.sh:/b.sh:ro" "$tools" sh /b.sh rsync /dest >/dev/null 2>&1; then
  fail "missing AGE_RECIPIENT did not fail"
fi

for d in rsync rclone; do
  [ "$(ls "$tmp/$d")" = "$snap.age
$cfgname" ] || fail "$d destination holds '$(ls "$tmp/$d")', want $snap.age and $cfgname"
  copy=$tmp/$d/$snap.age
  chmod a+r "$copy"
  # Control: the plain snapshot is a readable SQLite file with the user in it,
  # so the checks below can fail.
  tool -v "$tmp/bk:/x:ro" "$tools" sqlite3 "/x/$snap" 'select count(*) from sqlite_master' >/dev/null || fail "control: snapshot is not readable SQLite"
  grep -q "$email" "$tmp/bk/$snap" || fail "control: the plain snapshot does not hold the fixture email"
  # The copy is age output, not SQLite, and holds no plain text.
  head -c 21 "$copy" | grep -q '^age-encryption.org/v1' || fail "$d copy is not an age file"
  head -c 15 "$copy" | grep -q 'SQLite format 3' && fail "$d copy has the SQLite header"
  grep -q "$email" "$copy" && fail "$d copy holds the fixture email in clear"
  if tool -v "$tmp/$d:/x:ro" "$tools" sqlite3 "/x/$snap.age" 'select count(*) from sqlite_master' >/dev/null 2>&1; then
    fail "$d copy is readable as SQLite"
  fi
  # Without the private key, or with another key, it does not decrypt.
  if tool -v "$tmp/$d:/x:ro" -v "$tmp/priv:/priv:ro" "$tools" age -d -i /priv/other.txt "/x/$snap.age" >/dev/null 2>&1; then
    fail "$d copy decrypts with a key that is not the private key"
  fi
done

# The config copy: not a tar, no key material in clear, and with the private
# key it unpacks to the files of the config directory. Control: the plain tar
# of the directory is readable and holds the fixture secret.
tool -v "$tmp/c:/c:ro" "$tools" tar -C /c -cf - . 2>/dev/null | grep -qF fixture-client-secret || fail "control: the plain tar does not hold the fixture secret"
for d in rsync rclone; do
  cc=$tmp/$d/$cfgname
  chmod a+r "$cc"
  head -c 21 "$cc" | grep -q '^age-encryption.org/v1' || fail "$d config copy is not an age file"
  grep -qF fixture-client-secret "$cc" && fail "$d config copy holds a fixture secret in clear"
  if tool -v "$tmp/$d:/x:ro" "$tools" tar -tf "/x/$cfgname" >/dev/null 2>&1; then
    fail "$d config copy is readable as a tar"
  fi
  if tool -v "$tmp/$d:/x:ro" -v "$tmp/priv:/priv:ro" "$tools" age -d -i /priv/other.txt "/x/$cfgname" >/dev/null 2>&1; then
    fail "$d config copy decrypts with a key that is not the private key"
  fi
done
mkdir "$tmp/cfgout"
tool -v "$tmp/rsync:/x:ro" -v "$tmp/priv:/priv:ro" -v "$tmp/cfgout:/out" "$tools" sh -c "age -d -i /priv/key.txt -o /out/c.tar /x/$cfgname && mkdir /out/c && tar -C /out/c -xf /out/c.tar" || fail "config copy did not decrypt and unpack"
diff -r "$tmp/c" "$tmp/cfgout/c" >/dev/null || fail "decrypted config differs from the config directory"

# With the private key it decrypts to the snapshot exactly.
tool -v "$tmp/rsync:/x:ro" -v "$tmp/priv:/priv:ro" -v "$tmp/restore:/out" "$tools" age -d -i /priv/key.txt -o "/out/featherauth.db" "/x/$snap.age"
cmp "$tmp/restore/featherauth.db" "$tmp/bk/$snap" || fail "decrypted copy differs from the snapshot"

# Restore on a fresh data directory (the original one is not mounted): the
# service starts on it, is ready, and knows the imported user.
chmod -R a+rwX "$tmp/restore"
docker run -d --name "$svc" -e FEATHERAUTH_CONFIG_DIR=/etc/featherauth \
  -v "$tmp/c:/etc/featherauth:ro" -v "$tmp/restore:/var/lib/featherauth" "$img" >/dev/null
i=0
until docker exec "$svc" /featherauth healthcheck >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 30 ] || { docker logs "$svc"; fail "restored service did not become ready"; }
  sleep 1
done
# The restored database has the imported user, by email and by name.
users=$(docker exec "$svc" /featherauth user list example --email "$email")
printf '%s' "$users" | grep -q "\"email\": *\"$email\"" || fail "restored database lacks the user $email"
printf '%s' "$users" | grep -q '"name": *"Offsite Fixture"' || fail "restored user has the wrong name"
# The restored service answers discovery and the JWKS (from the service's own
# network namespace, as the container has no shell or wget).
get() { docker run --rm --network "container:$svc" "$tools" wget -q -O - "http://127.0.0.1:8080/example/$1"; }
get .well-known/openid-configuration | grep -q '"issuer": *"http://localhost:8080/example"' || fail "restored service did not answer discovery"
get jwks.json | grep -q '"kid"' || fail "restored service did not publish the JWKS"
echo "offsite backup checks passed"
