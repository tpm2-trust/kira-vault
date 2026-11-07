BINARY  := kira-vault
PREFIX  ?= /usr
UNITDIR ?= /usr/lib/systemd/system

.PHONY: build release-check container install-container test-container test test-integration vet fmt install clean

ENGINE ?= $(shell command -v podman || command -v docker)

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

# The image: the release binary alone (packaging/Containerfile).
container: build
	$(ENGINE) build -f packaging/Containerfile -t localhost/kira-vault:latest .

# The Quadlet, with this host's tss group (podman, as root).
install-container: container
	@gid=$$(getent group tss | cut -d: -f3); test -n "$$gid" || { echo "no tss group on this host" >&2; exit 1; }; \
	install -d $(DESTDIR)/etc/containers/systemd; \
	sed "s/@TSS_GID@/$$gid/g" packaging/kira-vault.container.in > $(DESTDIR)/etc/containers/systemd/kira-vault.container

# The container: it builds and locks; with VAULT_TEST_TPM=1 and a TPM, a vault is made in it.
test-container: build
	ENGINE=$(ENGINE) packaging/test-container.sh

install: build
	install -Dm0755 $(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	install -Dm0644 packaging/kira-vault.service $(DESTDIR)$(UNITDIR)/kira-vault.service

clean:
	rm -f $(BINARY)
