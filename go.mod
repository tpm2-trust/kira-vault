module github.com/tpm2-trust/kira-vault

go 1.26.0

require (
	github.com/google/go-attestation v0.6.4
	github.com/google/go-tpm v0.9.9-0.20261030171821-c395998989d7
	github.com/tpm2-trust/go-tui-slim v0.0.0
	github.com/tpm2-trust/go-uefi-slim v0.0.0
	github.com/tpm2-trust/kira/core v0.0.0
	golang.org/x/sys v0.49.0
)

require (
	github.com/tpm2-trust/tpm2-verifier v0.0.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.57.0 // indirect
)

// kira's shared core (attest, vaultproto) alone, not kira: from
// the submodule kira/, the commit it pins (../pin kira moves it).
replace github.com/tpm2-trust/kira/core => ./kira/core

// The core's EK root store, tpm2-verifier: the pinned kira's own
// submodule (git submodule update --init --recursive).
replace github.com/tpm2-trust/tpm2-verifier => ./kira/tpm2-verifier

// go-tui-slim (the control panel, its questions, the secrets' memory) and
// go-uefi-slim (the vault host's Secure Boot): the vault's own submodules, not
// kira/'s, so that they move with the vault's pins (../pin go-tui-slim,
// ../pin go-uefi-slim).
replace github.com/tpm2-trust/go-tui-slim => ./go-tui-slim

replace github.com/tpm2-trust/go-uefi-slim => ./go-uefi-slim
