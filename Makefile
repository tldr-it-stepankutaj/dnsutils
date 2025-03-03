BINARY_NAME=securitydns
VERSION=1.0.2
BUILD_DIR=bin

build:
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/main.go

build-all:
	mkdir -p $(BUILD_DIR)
	GOOS=linux   GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/main.go
	GOOS=linux   GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/main.go
	GOOS=darwin  GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/main.go
	GOOS=darwin  GOARCH=arm64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/main.go
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/main.go

clean:
	rm -rf $(BUILD_DIR)