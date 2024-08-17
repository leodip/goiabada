serve:	
	$$HOME/go/bin/air -c .air.toml

build:
	tailwindcss -c ./web/tailwindcss/tailwind.config.js -i ./web/tailwindcss/input.css -o ./web/static/main.css
	rm -f ./tmp/goiabada_auth_server
	go build -o ./tmp/goiabada_auth_server ./cmd/goiabada/main.go

test-ci: build
	./run-tests.sh
	rm -f /tmp/goiabada.db

test-local:   
	$(info For this Makefile target you need to run 'make serve' first, to start the server)
	go test -v -count=1 -p 1 ./tests/data/...
	go test -v -count=1 -p 1 ./tests/integration/...

cert:
	openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout ../cert/self_signed_key.pem -out ../cert/self_signed_cert.pem -batch

check:	
	unparam -exported ./...
	gocritic check ./...
	staticcheck ./...
	golangci-lint run ./...