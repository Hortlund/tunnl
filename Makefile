.PHONY: build test test-race lint clean

build:
	go build -trimpath -o bin/tunnl ./cmd/tunnl
	go build -trimpath -o bin/tunnld ./cmd/tunnld

test:
	go test ./...

test-race:
	go test -race ./...

lint:
	go vet ./...

clean:
	rm -rf bin dist
