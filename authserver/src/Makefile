serve:	
	$$HOME/go/bin/air -c .air.toml

build:
	tailwindcss -c ./web/tailwindcss/tailwind.config.js -i ./web/tailwindcss/input.css -o ./web/static/main.css
	rm -f ./tmp/goiabada
	go build -o ./tmp/goiabada ./cmd/goiabada/main.go

test:	
	$(info Please note that you must have a goiabada webserver running for the tests to run. If you don't have it, try `make serve` in another terminal window.)
	go clean -cache
	go test -v -count=1 -p 1 ./cmd/integration_tests/...

cert:
	openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout ../cert/self_signed_key.pem -out ../cert/self_signed_cert.pem -batch