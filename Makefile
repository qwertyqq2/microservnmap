build:
	go build cmd/main.go

lint:
	golint ./...

test:
	go test ./service/parser ./service -timeout 100s