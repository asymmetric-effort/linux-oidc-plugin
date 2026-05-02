.PHONY: clean lint test build release

VERSION := $(shell cat VERSION)
BINARY := pam-oidc
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

clean:
	rm -rf ./bin
	mkdir -p ./bin

lint:
	go vet -v ./...
	staticcheck ./...
	govulncheck ./...

test:
	go test -v -race -count=1 -failfast -coverprofile=coverage.out ./...
	@echo ""
	@echo "Coverage summary:"
	@go tool cover -func=coverage.out | tail -1

build: clean
	go build $(LDFLAGS) -o ./bin/$(BINARY) ./cmd/pam-oidc

release: clean
	@OLD_VERSION=$$(cat VERSION); \
	MAJOR=$$(echo $$OLD_VERSION | cut -d. -f1); \
	MINOR=$$(echo $$OLD_VERSION | cut -d. -f2); \
	PATCH=$$(echo $$OLD_VERSION | cut -d. -f3); \
	NEW_PATCH=$$((PATCH + 1)); \
	NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	echo "$$NEW_VERSION" > VERSION; \
	echo "Bumped version: $$OLD_VERSION -> $$NEW_VERSION"; \
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=$$NEW_VERSION" -o ./bin/$(BINARY)-linux-amd64 ./cmd/pam-oidc; \
	GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=$$NEW_VERSION" -o ./bin/$(BINARY)-linux-arm64 ./cmd/pam-oidc; \
	tar -czf ./bin/$(BINARY)-$$NEW_VERSION-linux-amd64.tar.gz -C ./bin $(BINARY)-linux-amd64; \
	tar -czf ./bin/$(BINARY)-$$NEW_VERSION-linux-arm64.tar.gz -C ./bin $(BINARY)-linux-arm64; \
	echo "Release artifacts in ./bin/"
