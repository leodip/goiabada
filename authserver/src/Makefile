serve:	
	$$HOME/go/bin/air -c .air.toml

build:
	tailwindcss -c ./web/tailwindcss/tailwind.config.js -i ./web/tailwindcss/input.css -o ./web/static/main.css
	rm -f ./tmp/goiabada
	go build -o ./tmp/goiabada ./cmd/goiabada/main.go

test-sqlite: export GOIABADA_DB_TYPE=sqlite
test-sqlite: export GOIABADA_DB_DSN=/tmp/goiabada.db
test-sqlite: export GOIABADA_LOGGER_ROUTER_HTTPREQUESTS_ENABLED=false
test-sqlite: export GOIABADA_AUDITING_CONSOLELOG_ENABLED=false
test-sqlite: export GOIABADA_LOGGER_GORM_TRACEALL=false
test-sqlite: build
	./run-tests.sh
	rm -f /tmp/goiabada.db

test-mysql: export GOIABADA_DB_TYPE=mysql
test-mysql: export GOIABADA_DB_DSN=
test-mysql: export GOIABADA_DB_HOST=mysql-server
test-mysql: export GOIABADA_DB_PORT=3306
test-mysql: export GOIABADA_DB_DBNAME=goiabada
test-mysql: export GOIABADA_DB_USERNAME=root
test-mysql: export GOIABADA_DB_PASSWORD=abc123
test-mysql: export GOIABADA_LOGGER_ROUTER_HTTPREQUESTS_ENABLED=false
test-mysql: export GOIABADA_AUDITING_CONSOLELOG_ENABLED=false
test-mysql: export GOIABADA_LOGGER_GORM_TRACEALL=false
test-mysql: build
	./run-tests.sh

cert:
	openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout ../cert/self_signed_key.pem -out ../cert/self_signed_cert.pem -batch