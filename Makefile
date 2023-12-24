.PHONY: test
test:
	go test -v -race -cover -bench=. ./...

lint-local:
	golangci-lint run
