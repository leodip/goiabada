serve:	
	$$HOME/go/bin/air -c .air.toml

build:
	tailwindcss -c ./web/tailwindcss/tailwind.config.js -i ./web/tailwindcss/input.css -o ./web/static/main.css
	rm -f ./tmp/goiabada-adminconsole
	go build -o ./tmp/goiabada-adminconsole ./cmd/goiabada-adminconsole/main.go

check:	
	unparam -exported ./...	
	staticcheck ./...
	golangci-lint run ./...
