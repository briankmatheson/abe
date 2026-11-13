# abe — build, test, package, deploy.
#
#   make                 debug build
#   make test            cargo test + tests/lint-links.sh
#   make lint            fmt --check + clippy
#   make e2e             sudo tests/e2e.sh (needs a thin pool, fio, nvme-cli)
#   make deb             target/debian/abe_<ver>-1_<arch>.deb (needs cargo-deb)
#   make install         install that .deb on this box
#   make deploy HOSTS="timesink gram"   scp + install the .deb on remote boxes
#   make tag             git tag v<ver> from Cargo.toml (annotated)
#   make push            git push --follow-tags
#
# Version comes from Cargo.toml. Bump it there first.

SHELL    := /bin/bash
CARGO    ?= cargo
VERSION  := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
ARCH     := $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
DEB      := target/debian/abe_$(VERSION)-1_$(ARCH).deb
HOSTS    ?=
SSH_USER ?= $(USER)

.DEFAULT_GOAL := build
.PHONY: build release test lint fmt clippy e2e deb install deploy tag push clean version help

build:
	$(CARGO) build

release:
	$(CARGO) build --release

test:
	$(CARGO) test
	tests/lint-links.sh

fmt:
	$(CARGO) fmt

lint:
	$(CARGO) fmt -- --check
	$(CARGO) clippy --all-targets -- -D warnings

clippy: lint

# Root, a real thin pool and fio: see tests/e2e.sh for the env it reads.
e2e:
	sudo tests/e2e.sh

# cargo-deb builds the release binary itself.
deb:
	@$(CARGO) deb --version >/dev/null 2>&1 || { echo "cargo-deb missing: cargo install cargo-deb"; exit 1; }
	$(CARGO) deb
	@ls -l $(DEB)

$(DEB): deb

# Debian ships an unrelated package also called "abe" (the SDL game). If it is
# installed, apt sees our version as a downgrade; remove it first.
install: $(DEB)
	@if dpkg -s abe 2>/dev/null | grep -q "^Version: 1\."; then \
	  echo "the Debian 'abe' game is installed; removing it first"; \
	  sudo apt remove -y abe abe-data; fi
	sudo apt install -y ./$(DEB)

# make deploy HOSTS="timesink gram"  (ssh as $(SSH_USER); sudo must work there)
deploy: $(DEB)
	@test -n "$(HOSTS)" || { echo "usage: make deploy HOSTS=\"box1 box2\""; exit 1; }
	@for h in $(HOSTS); do \
	  echo "== $$h"; \
	  scp $(DEB) $(SSH_USER)@$$h:/tmp/ && \
	  ssh -t $(SSH_USER)@$$h "sudo apt install -y /tmp/$(notdir $(DEB)) && systemctl is-active abe; . /etc/default/abe 2>/dev/null; curl -sf http://\$${ABE_LISTEN:-127.0.0.1:80}/version; echo" || exit 1; \
	done

tag:
	@git diff --quiet || { echo "working tree not clean"; exit 1; }
	git tag -a v$(VERSION) -m "abe v$(VERSION)"
	@echo "tagged v$(VERSION); now: make push"

push:
	git push --follow-tags

clean:
	$(CARGO) clean

version:
	@echo $(VERSION)

help:
	@sed -n '2,13p' Makefile | sed 's/^# \{0,1\}//'
