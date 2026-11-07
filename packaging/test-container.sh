#!/bin/sh
# The container: it builds; under a memlock limit a command that holds secrets
# refuses before anything else, without one it gets past the lock; with a TPM device
# on this machine a vault is made in it. Run by make test-container.
set -eu
engine=${ENGINE:-$(command -v podman || command -v docker)}
image=localhost/kira-vault:test
fail() { echo "FAIL: $*" >&2; exit 1; }

"$engine" build -q -f packaging/Containerfile -t "$image" . >/dev/null || fail "the image does not build"
out=$("$engine" run --rm "$image" help) || fail "help: $out"
echo "$out" | grep -q "kira-vault init" || fail "help says no init"
echo "ok: the image builds and runs"

out=$("$engine" run --rm --ulimit memlock=65536:65536 "$image" init 2>&1) && fail "init ran under a memlock limit"
echo "$out" | grep -q "not locked in memory" || fail "under a memlock limit: $out"
echo "ok: under a memlock limit, init refuses before it holds anything"

out=$("$engine" run --rm --ulimit memlock=-1:-1 "$image" init 2>&1) && fail "init ran without a TPM"
echo "$out" | grep -q "not locked in memory" && fail "with no memlock limit: $out"
echo "$out" | grep -q "/dev/tpmrm0" || fail "with no memlock limit, no TPM: $out"
echo "ok: with no memlock limit it gets past the lock, to the TPM"

if [ ! -e /dev/tpmrm0 ]; then
    echo "skipped: a vault made in the container - this machine has no /dev/tpmrm0"
    exit 0
fi
if [ "${VAULT_TEST_TPM:-}" != 1 ]; then
    echo "skipped: a vault made in the container - it defines NV 0x01804000 and keys in this machine's TPM (VAULT_TEST_TPM=1 to run it)"
    exit 0
fi
dir=$(mktemp -d)
mkdir -m 0700 "$dir/state" "$dir/run"
gid=$(stat -c %g /dev/tpmrm0)
printf 'container-pin\ncontainer-pin\n' | "$engine" run --rm -i --device /dev/tpmrm0 --group-add "$gid" --ulimit memlock=-1:-1 \
    -v "$dir/state:/var/lib/kira-vault" -v "$dir/run:/run/kira-vault" "$image" init --pcrs 23 --url https://localhost:8443 \
    | grep -q "Initialised the vault" || fail "init with the TPM (its state in $dir)"
echo "ok: a vault made in the container with this machine's TPM (its state in $dir: remove it, and the counter at 0x01804000 of this TPM)"
