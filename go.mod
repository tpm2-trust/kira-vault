module github.com/tpm2-trust/kira-vault

go 1.26.0

require (
	github.com/google/go-tpm v0.9.9-0.20261030171821-c395998989d7
	github.com/tpm2-trust/kira/core v0.0.0
	golang.org/x/sys v0.48.0
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
