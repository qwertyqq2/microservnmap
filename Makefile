build:
	go build cmd/main.go

linter:
	go golangci-lint run

test:
	go test ./service/parser ./service 