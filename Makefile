BINARY := mesh-debug
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST := dist

.PHONY: test build build-all clean

test:
	go test -v -race ./...

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY) ./cmd/mesh-debug

build-all: clean
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64 ./cmd/mesh-debug
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-arm64 ./cmd/mesh-debug
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-windows-amd64.exe ./cmd/mesh-debug
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-darwin-arm64 ./cmd/mesh-debug

clean:
	rm -rf $(DIST)
