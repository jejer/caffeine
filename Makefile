all: prepare linux windows darwin

prepare:
	rm -rf ./bin
	mkdir ./bin

linux: linux-amd64 linux-arm64

windows: windows-amd64

darwin: darwin-amd64

linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o ./bin/caffeine-linux-amd64

linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o ./bin/caffeine-linux-arm64

windows-amd64:
	GOOS=windows GOARCH=amd64 go build -o ./bin/caffeine-windows-amd64

darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -o ./bin/caffeine-darwin-amd64
