.PHONY: build test fmt

build:
	go build -trimpath -o bin/wiseguard ./cmd/wiseguard

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')
