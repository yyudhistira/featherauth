#!/bin/sh
# CI check of the setup with the image alone (OPS-21). Needs docker and openssl
# (on the host, for the key types). Run from the repository root:
# deploy/ops/check-setup.sh
# CHECK_SETUP_IMAGE is a test hook: it names an image to check instead of
# building one from deploy/Dockerfile.
#
# It runs the one-off containers of "Setup with the image alone" in DESIGN.md
# with the candidate image: the service's user (65532:65532), no network, a
# read-only root and the configuration directory mounted read-write, on an empty
# directory owned by uid 65532: config init, keys generate for RSA, EC P-256 and
# an encryption key, and config check. It then asserts the files, their owners and
# modes, the key types, that keys generate refuses to overwrite, and that config
# check reports no permission diagnostic.
#
# The shipped example realm names its key secrets/example/signing-2026-10.pem, so
# the RSA key is written there: config check then finds every file it needs.
#
# The directory is a new docker volume, so that owners and modes are those of a
# Linux file system on every host (a bind mount on Docker Desktop reports
# arbitrary owners). A throwaway Alpine container (pinned by digest, as
# check-offsite.sh) prepares it and reads files owned by uid 65532 as root.
set -eu

alpine_img=alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
built=
if [ -n "${CHECK_SETUP_IMAGE:-}" ]; then
  img=$CHECK_SETUP_IMAGE
else
  img=featherauth-ci-setup:latest
  built=1
fi
tmp=$(mktemp -d)
conf=featherauth-ci-setup-config
out=$tmp/out
cleanup() {
  docker volume rm -f "$conf" >/dev/null 2>&1 || true
  [ -z "$built" ] || docker rmi "$img" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

if [ -n "$built" ]; then
  docker build -q -f deploy/Dockerfile -t "$img" . >/dev/null
fi

# The directory is created first, owned by 65532, as the design's install does.
docker volume rm -f "$conf" >/dev/null 2>&1 || true
docker volume create "$conf" >/dev/null
docker run --rm --user 0 -v "$conf:/c" "$alpine_img" sh -c 'chown 65532:65532 /c && chmod 700 /c'

# root runs a command as root in a container that mounts the directory.
root() { docker run --rm --user 0 -v "$conf:/c" "$alpine_img" "$@"; }
# run is the one-off container of the design.
run() { docker run --rm --user 65532:65532 --network none --read-only -v "$conf:/etc/featherauth" "$img" "$@"; }
# step runs a command and fails unless it exits 0; its output goes to $out.
step() {
  if ! run "$@" >"$out" 2>&1; then
    cat "$out"
    fail "featherauth $* did not exit 0"
  fi
}

rsa=secrets/example/signing-2026-10.pem
ec=secrets/example/signing-ec-1.pem
enc=secrets/encryption_key

step config init /etc/featherauth
step keys generate "/etc/featherauth/$rsa"
step keys generate --type ec "/etc/featherauth/$ec"
step keys generate --type encryption "/etc/featherauth/$enc"
echo "setup commands ok"

# config check: exits 0, prints nothing but ok, so no permission diagnostic.
step config check /etc/featherauth
[ "$(cat "$out")" = ok ] || { cat "$out"; fail "config check printed more than ok"; }
echo "config check ok"

# The configuration files exist.
for f in server.yaml database.yaml realms/example.yaml locales/en.yaml.example; do
  root test -f "/c/$f" || fail "$f was not written"
done
echo "config files ok"

# The three keys: owner 65532:65532 and mode 0600.
for f in $rsa $ec $enc; do
  got=$(root stat -c '%u:%g %a' "/c/$f")
  [ "$got" = "65532:65532 600" ] || fail "$f has owner and mode $got, want 65532:65532 600"
done
echo "key owner and mode ok"

# Key types: RSA of 2048 bits, EC P-256, and 44 base64 characters of 32 bytes.
root cat "/c/$rsa" | openssl pkey -noout -text >"$out" 2>&1 || fail "$rsa is not a private key"
grep -q '(2048 bit' "$out" && grep -q modulus "$out" || fail "$rsa is not an RSA key of 2048 bits"
root cat "/c/$ec" | openssl pkey -noout -text >"$out" 2>&1 || fail "$ec is not a private key"
grep -Eq 'prime256v1|P-256' "$out" || fail "$ec is not an EC P-256 key"
n=$(root cat "/c/$enc" | tr -d '\n' | wc -c | tr -d ' ')
[ "$n" = 44 ] || fail "$enc holds $n characters, want 44"
n=$(root cat "/c/$enc" | tr -d '\n' | openssl base64 -d -A | wc -c | tr -d ' ')
[ "$n" = 32 ] || fail "$enc holds $n bytes, want 32"
echo "key types ok"

# keys generate refuses to overwrite: exit 1, the file unchanged.
for f in $rsa $ec $enc; do
  before=$(root sh -c "sha256sum /c/$f; stat -c '%u:%g %a' /c/$f")
  t=rsa
  case $f in *ec-1*) t=ec ;; *encryption_key) t=encryption ;; esac
  rc=0
  run keys generate --type "$t" "/etc/featherauth/$f" >"$out" 2>&1 || rc=$?
  [ "$rc" = 1 ] || fail "a second keys generate on $f exited $rc, want 1"
  after=$(root sh -c "sha256sum /c/$f; stat -c '%u:%g %a' /c/$f")
  [ "$before" = "$after" ] || fail "a refused keys generate changed $f"
done
echo "keys generate refuses to overwrite ok"

# The permission check can see a problem: with the encryption key at 0644 it
# reports one, so the ok above is not an absent check.
root chmod 644 "/c/$enc"
rc=0
run config check /etc/featherauth >"$out" 2>&1 || rc=$?
[ "$rc" = 1 ] || fail "config check exited $rc with a key at mode 0644, want 1"
grep -q 'must not be accessible by group or others' "$out" || { cat "$out"; fail "config check did not report the mode of $enc"; }
echo "permission diagnostic seen ok"

echo "setup check passed"
