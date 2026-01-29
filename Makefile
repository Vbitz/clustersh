.PHONY: all build test clean install install-coordinator install-agent install-client fmt lint

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"
PREFIX ?= $(HOME)/.local

all: build

build:
	go build $(LDFLAGS) -o bin/clusterd ./cmd/clusterd
	go build $(LDFLAGS) -o bin/clusteragent ./cmd/clusteragent
	go build $(LDFLAGS) -o bin/clustersh ./cmd/clustersh

test:
	go test -v ./...

test-integration:
	go test -v -tags=integration ./...

clean:
	rm -rf bin/
	go clean

install:
	go install $(LDFLAGS) ./cmd/clusterd
	go install $(LDFLAGS) ./cmd/clusteragent
	go install $(LDFLAGS) ./cmd/clustersh

install-coordinator: bin/clusterd
	@mkdir -p $(PREFIX)/bin
	cp bin/clusterd $(PREFIX)/bin/clusterd
	@echo "Installed clusterd to $(PREFIX)/bin/clusterd"

install-agent: bin/clusteragent
	@mkdir -p $(PREFIX)/bin
	cp bin/clusteragent $(PREFIX)/bin/clusteragent
	@echo "Installed clusteragent to $(PREFIX)/bin/clusteragent"

install-client: bin/clustersh
	@mkdir -p $(PREFIX)/bin
	cp bin/clustersh $(PREFIX)/bin/clustersh
	@echo "Installed clustersh to $(PREFIX)/bin/clustersh"

bin/clusterd: $(shell find . -name '*.go' -type f)
	go build $(LDFLAGS) -o bin/clusterd ./cmd/clusterd

bin/clusteragent: $(shell find . -name '*.go' -type f)
	go build $(LDFLAGS) -o bin/clusteragent ./cmd/clusteragent

bin/clustersh: $(shell find . -name '*.go' -type f)
	go build $(LDFLAGS) -o bin/clustersh ./cmd/clustersh

fmt:
	go fmt ./...

lint:
	golangci-lint run

# Cross-compilation targets
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

release: clean
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "Building $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o bin/clusterd-$$os-$$arch$$ext ./cmd/clusterd; \
		GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o bin/clusteragent-$$os-$$arch$$ext ./cmd/clusteragent; \
		GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o bin/clustersh-$$os-$$arch$$ext ./cmd/clustersh; \
	done
