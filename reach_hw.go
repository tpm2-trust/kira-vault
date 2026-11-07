//go:build !vault_test_swtpm

package main

// socketTPM: a release takes a hardware TPM alone (reach.go).
const socketTPM = false
