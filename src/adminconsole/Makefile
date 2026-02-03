# If GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE is set, use it; otherwise default to /tmp path
BOOTSTRAP_ENV ?= $(if $(GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE),$(GOIABADA_AUTHSERVER_BOOTSTRAP_ENV_OUTFILE),/tmp/goiabada/adminconsole.env)

serve:
	@if [ -f "$(BOOTSTRAP_ENV)" ]; then \
		echo "[adminconsole] Loading bootstrap env from $(BOOTSTRAP_ENV)"; \
		set -a; . "$(BOOTSTRAP_ENV)"; set +a; \
	elif [ -z "$$GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID" ] || [ -z "$$GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET" ]; then \
		echo "[adminconsole] ERROR: Bootstrap env NOT found at $(BOOTSTRAP_ENV) and required env vars not set."; \
		echo "[adminconsole] Start the authserver first to generate $(BOOTSTRAP_ENV), or export GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_ID and GOIABADA_ADMINCONSOLE_OAUTH_CLIENT_SECRET."; \
		exit 1; \
	fi; \
	air -c .air.toml

build:
	./build.sh

check:	
	unparam -exported ./...	
	staticcheck ./...
	golangci-lint run ./...

format:
	gofmt -w -s .
