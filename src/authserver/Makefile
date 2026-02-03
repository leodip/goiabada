serve:	
	air -c .air.toml

build:
	./build.sh

test-ci:
	./run-tests.sh

test-local:   
	$(info For this Makefile target you need to run 'make serve' first, to start the server)
	go test -v -count=1 -p 1 ./tests/integration/...
	go test -v -count=1 -p 1 ./tests/data/...	

cert:
	openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout ../cert/self_signed_key.pem -out ../cert/self_signed_cert.pem -batch

check:	
	unparam -exported ./...	
	staticcheck ./...
	golangci-lint run ./...
