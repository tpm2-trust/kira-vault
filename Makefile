BINARY  := kira-vault
PREFIX  ?= /usr
UNITDIR ?= /usr/lib/systemd/system

.PHONY: build release-check test test-integration vet fmt install clean

# The release builds the pinned core (the submodule kira/), never a
# go.work around this checkout.
build:
	GOWORK=off CGO_ENABLED=0 go build -trimpath -o $(BINARY) .
	@$(MAKE) --no-print-directory release-check

# A release is never a test build: the tag vault_test_swtpm lets init take a software
# TPM's socket (reach_swtpm.go), which binds the vault's keys to nothing.
release-check:
	@if go version -m $(BINARY) | grep -q 'vault_test_swtpm'; then \
		echo "$(BINARY) is a test build (vault_test_swtpm): not for a release" >&2; rm -f $(BINARY); exit 1; fi

test:
	go test ./...

# Needs swtpm.
test-integration:
	go test -count=1 -tags integration ./...

vet:
	go vet ./...
	go vet -tags integration ./...

fmt:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; exit 1; }

install: build
	install -Dm0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -Dm0644 packaging/kira-vault.service $(DESTDIR)$(UNITDIR)/kira-vault.service

clean:
	rm -f $(BINARY)
