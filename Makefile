# abe — build, test, package, deploy.
#
#   make                 debug build
#   make test            cargo test + tests/lint-links.sh
#   make lint            fmt --check + clippy
#   make e2e             sudo tests/e2e.sh (needs a thin pool, fio, nvme-cli)
#   make deb             target/debian/abe-block-exporter_<ver>-1_<arch>.deb (needs cargo-deb)
#   make install         install that .deb on this box
#   make deploy HOSTS="timesink gram"   scp + install the .deb on remote boxes
#   make tag             git tag v<ver> from Cargo.toml (annotated)
#   make push            git push --follow-tags
#
# Version comes from Cargo.toml. Bump it there first.

SHELL    := /bin/bash
CARGO    ?= cargo
VERSION  := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
REVISION := $(shell sed -n 's/^revision = "\(.*\)"/\1/p' Cargo.toml | head -1)
REVISION := $(if $(REVISION),$(REVISION),1)
ARCH     := $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
DEB      := target/debian/abe-block-exporter_$(VERSION)-$(REVISION)_$(ARCH).deb
HOSTS    ?=
SSH_USER ?= $(USER)

# GET /version on the box after an install, with the TLS settings from its
# /etc/default/abe (same derivation as tests/e2e.sh; sudo reads the key).
# VERIFY runs locally; REMOTE_VERIFY is the same inside an ssh "..." string.
VERIFY := . /etc/default/abe 2>/dev/null; \
  if [ x$${ABE_TLS:-on} = xoff ]; then CURL=curl; S=http; \
  else CURL='sudo curl --cacert '$${ABE_TLS_CA:-/etc/abe/ca.pem}' --cert '$${ABE_TLS_CERT:-/etc/abe/cert.pem}' --key '$${ABE_TLS_KEY:-/etc/abe/key.pem}; S=https; fi; \
  U=$$S://$$(echo $${ABE_LISTEN:-127.0.0.1:443} | sed s/0.0.0.0/127.0.0.1/)/version; \
  $$CURL -sf $$U && echo || { echo '!! abe is not answering' $$U '-- see: sudo journalctl -u abe -n 20 and /etc/default/abe'; false; }
REMOTE_VERIFY = $(subst $$,\$$,$(VERIFY))

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

# Conflicts with Debian's unrelated "abe" (an SDL game): apt errors out if
# that is installed. Remove it yourself (apt remove abe abe-data) first.
install: $(DEB)
	sudo apt install -y --reinstall -o Dpkg::Options::=--force-confold ./$(DEB) && sudo systemctl restart abe
	@$(VERIFY)

# make deploy HOSTS="timesink gram"  (ssh as $(SSH_USER); sudo must work there)
deploy: $(DEB)
	@test -n "$(HOSTS)" || { echo "usage: make deploy HOSTS=\"box1 box2\""; exit 1; }
	@for h in $(HOSTS); do \
	  echo "== $$h"; \
	  scp $(DEB) $(SSH_USER)@$$h:/tmp/ && \
	  ssh -t $(SSH_USER)@$$h "sudo apt install -y --reinstall -o Dpkg::Options::=--force-confold /tmp/$(notdir $(DEB)) && sudo systemctl restart abe && systemctl is-active abe; $(REMOTE_VERIFY)" || exit 1; \
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
