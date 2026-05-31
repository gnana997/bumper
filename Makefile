.PHONY: build test run tidy fmt vet hooks tools corpus

build:
	go build -o bumper ./cmd/bumper

test:
	go test ./...

# Run against the bundled fixture: make run
run: build
	./bumper internal/engine/testdata/plan.json || true

tidy:
	go mod tidy

fmt:
	go fmt ./...

vet:
	go vet ./...

# Install the dev tools the git hooks depend on (lefthook + gitleaks).
tools:
	@command -v lefthook >/dev/null 2>&1 || go install github.com/evilmartians/lefthook@latest
	@command -v gitleaks >/dev/null 2>&1 || go install github.com/zricethezav/gitleaks/v8@latest

# One-time setup after cloning: install hooks (pre-commit secret scan + gofmt).
hooks: tools
	lefthook install

# Scan the multi-cloud anti-pattern corpus (needs terraform on PATH).
corpus: build
	BUMPER=$(CURDIR)/bumper tools/corpus_scan.sh
