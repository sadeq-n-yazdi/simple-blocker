BINARY := simple-blocker
PKG     := ./cmd/simple-blocker

.PHONY: build test vet fmt lint clean install

build: ## Build the binary into ./dist
	@mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o dist/$(BINARY) $(PKG)

test: ## Run the test suite
	go test ./...

vet: ## Run go vet
	go vet ./...

fmt: ## Format the code
	gofmt -w .

clean: ## Remove build artifacts
	rm -rf dist

install: ## Build + install via the install script (needs root)
	sudo ./scripts/install.sh
