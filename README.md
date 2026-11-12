# kira-vault

The vault of [kira](../kira)'s keyslots with the vault's salt. Such
a keyslot's key is made from a password - held by the machine's TPM
(unattended) or typed at the machine - and a salt kept here, wrapped so
that only that machine's TPM opens it. At boot the machine's initrd asks
for it, and the vault releases it only to a fresh TPM quote of a boot
state that the machine's own signing key approved - at once, or once an
operator approves, with a pepper if the keyslot was enrolled with one. Each
record is encrypted under a key derived from one master in this vault's TPM,
which works only under an approval of the vault's own boot state, signed in the
same TPM behind the approval PIN; the master's backup, shown once at `init`, is the
vault's only recovery secret.

**The documentation is kira's
[docs/VAULT.md](../kira/docs/VAULT.md)**: the design and
threat model, setting up both sides, the protocol, the release rules (§6.1),
keys at rest and their approval (§6.2), the admin interface, the state directory,
recovery (§6.5), the commands (§6.6), the control panel (§6.7) and the tests. The contract with kira is its core's Go
package `github.com/tpm2-trust/kira/core/vaultproto`; this module requires
the core module alone, pinned by the git submodule `kira/` (`replace`
to `./kira/core` in go.mod).

## Build

```
git clone --recurse-submodules ...   # or: git submodule update --init --recursive
make build              # ./kira-vault, no cgo, the pinned core (GOWORK=off)
make test               # unit tests, no TPM
make test-integration   # with swtpm
sudo make install       # /usr/bin and the systemd unit
make container          # the image, the release binary alone (podman or docker)
make test-container     # it builds, locks its memory; with VAULT_TEST_TPM=1 and a TPM, is made
sudo make install-container   # the Quadlet for podman, with this host's tss group
```

## In short

```
vault#    kira-vault control                                          # the guided way; or by hand:
vault#    kira-vault init --url https://vault.example:8443            # the PIN twice; write down the backup
vault#    systemctl enable --now kira-vault                           # and open TCP 8443
vault#    kira-vault token create --name db-03                        # prints the machine's command
vault#    kira-vault tls root > vault-ca.pem                          # the machines' and operators' copy, no secret
machine#  kira luks enrol /dev/sda2 --password tpm --salt vault --url … --pin … --token … --ca vault-ca.pem
vault#    kira-vault status | devices | requests | audit
vault#    kira-vault requests answer                                  # approve, deny or skip; asks a pepper
vault#    kira-vault approve                                          # after a firmware or Secure Boot update
vault#    kira-vault device revoke db-03                              # a machine reported stolen: for good
vault#    kira-vault init --restore                                   # the TPM lost: the backup into another
```

The operator interface (off by default) lets operators approve releases
over the network, with the pepper of a device enrolled with one:

```
vault#    kira-vault config set operator-listen :8444    # serve stopped; or init --operator-listen :8444
vault#    kira-vault operator add alice                  # prints the bearer token once, and a curl example
anywhere$ curl --cacert vault-ca.pem -H "Authorization: Bearer $TOKEN" https://vault.example:8444/v1/requests
anywhere$ curl --cacert vault-ca.pem -H "Authorization: Bearer $TOKEN" \
            -d '{"pepper":"…"}' https://vault.example:8444/v1/requests/ID/approve
```

It serves `GET /v1/requests`, `POST /v1/requests/{id}/approve` (body `{}`
or `{"pepper":"…"}`), `POST /v1/requests/{id}/deny`, `GET /v1/devices` and
`GET /v1/devices/{id}`, nothing else, over TLS with the vault's own root
(`tls root`), which machines and operators verify the vault against.

No TLS private key is a file: the root's key - the pin's - follows from the master and
is in the vault's TPM beside it, and the leaf's key is made in memory at every start. A
copy or a backup of the state directory cannot play the vault, and a restore of the
master's backup keeps the pin (kira's `docs/VAULT.md`, §6.2).

A keyslot enrolled with `--keyboard-pepper` takes a pepper of the person's that no device keeps: with
every release the vault sends a seed for that boot, wrapped for the machine's TPM, and shows its
one-time keyboard layout, in `kira-vault requests` (a request in state `released`) and in
`layout` of `GET /v1/requests`, for 15 minutes, never in the audit. The person types the pepper at
the machine through it (kira's docs/VAULT.md §12a).

`kira-vault help` lists every command.
