GOPATH= $(shell go env GOPATH)

.PHONY: test
test:
	go test ./...

.PHONY: benchmark
benchmark:
	go test -benchmem -bench . .

.PHONY: lint
lint:
	go vet ./...
	GO111MODULE=on go get honnef.co/go/tools/cmd/staticcheck@2020.1.3
	$(GOPATH)/bin/staticcheck -go 1.14 ./...
