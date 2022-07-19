export PATH := $(GOPATH)/bin:C:/Program Files/Git/usr/bin:$(PATH)
export GO111MODULE=on
export GOPROXY=https://goproxy.cn,direct

main:
	env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o ./bin/output  ./go_proxy