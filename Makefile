
.PHONY: build test clean install

VERSION := 1.0.0
BINARY := obfuscator
GOFILES := $(shell find . -name "*.go" -type f)

build:
	go build -ldflags "-X main.Version=$(VERSION)" -o $(BINARY) .

test:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

benchmark:
	go test -bench=. -benchmem

install: build
	mkdir -p ~/.obfuscator
	cp $(BINARY) /usr/local/bin/
	cp config.yaml ~/.obfuscator/

clean:
	rm -f $(BINARY) coverage.out coverage.html
	rm -rf obfuscated/ restored/

docker-build:
	docker build -t obfuscator:$(VERSION) .

docker-run:
	docker run -it -v $(PWD):/workspace obfuscator:$(VERSION)

release:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY)-darwin-amd64
	GOOS=windows GOARCH=amd64 go build -o $(BINARY)-windows-amd64.exe

.DEFAULT_GOAL := build