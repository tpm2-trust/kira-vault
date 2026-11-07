//go:build vault_test_swtpm

package main

// socketTPM: a test build (the tag vault_test_swtpm, kira's vmtest) takes a software
// TPM's socket too. make build refuses a binary built with the tag.
const socketTPM = true
