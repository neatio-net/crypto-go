.PHONY: docs
REPO:=github.com/neatio-network/crypto-go

docs:
	@go get github.com/davecheney/godoc2md
	godoc2md $(REPO) > README.md

test:
	go test ./...
