serve:	
	$$HOME/go/bin/air -c .air.toml

build:
	./build.sh

check:	
	unparam -exported ./...	
	staticcheck ./...
	golangci-lint run ./...
