FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y curl
RUN apt-get install -y wget
RUN apt-get install -y nano
RUN apt-get install -y make
RUN apt-get install -y git
RUN apt-get install -y zip
RUN apt-get install -y ripgrep
RUN apt-get install -y openssl
RUN apt-get install -y python3
RUN apt-get install -y python3-pip
RUN apt-get install -y python3-venv
RUN rm -rf /var/lib/apt/lists/*

# Create and activate a virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip3 install mkdocs
RUN pip3 install mkdocs-material

# Install Go
RUN wget https://go.dev/dl/go1.25.0.linux-amd64.tar.gz -O /tmp/go1.25.0.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.25.0.linux-amd64.tar.gz
RUN rm -f /tmp/go1.25.0.linux-amd64.tar.gz
RUN echo "export PATH=$PATH:/usr/local/go/bin:/root/go/bin" >> ~/.bashrc

# Install Golang Air and Go tools
RUN /usr/local/go/bin/go install -v github.com/air-verse/air@latest
RUN /usr/local/go/bin/go install -v golang.org/x/tools/gopls@latest
RUN /usr/local/go/bin/go install -v github.com/go-delve/delve/cmd/dlv@latest
RUN /usr/local/go/bin/go install -v golang.org/x/tools/cmd/goimports@latest
RUN /usr/local/go/bin/go install -v honnef.co/go/tools/cmd/staticcheck@latest
RUN /usr/local/go/bin/go install -v github.com/cweill/gotests/gotests@latest
RUN /usr/local/go/bin/go install -v github.com/go-critic/go-critic/cmd/gocritic@latest
RUN /usr/local/go/bin/go install -v mvdan.cc/unparam@latest
RUN /usr/local/go/bin/go install -v github.com/go-critic/go-critic/cmd/gocritic@latest
RUN /usr/local/go/bin/go install -v github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0
RUN /usr/local/go/bin/go install -v github.com/vektra/mockery/v3@v3.5.3

# Install Tailwind CLI tool
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v4.1.12/tailwindcss-linux-x64
RUN chmod +x tailwindcss-linux-x64
RUN mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss

RUN mkdir -p /var/lib/sqlite

# Environment variables (config) ------------------------

ENV TZ="Europe/Lisbon"

ENV GOIABADA_ADMIN_EMAIL="admin@example.com"
ENV GOIABADA_ADMIN_PASSWORD="changeme"
ENV GOIABADA_APPNAME="Goiabada"

ENV GOIABADA_AUTHSERVER_BASEURL="http://localhost:9090"
ENV GOIABADA_AUTHSERVER_INTERNALBASEURL=""
ENV GOIABADA_AUTHSERVER_LISTEN_HOST_HTTPS="0.0.0.0"
ENV GOIABADA_AUTHSERVER_LISTEN_PORT_HTTPS=9443
ENV GOIABADA_AUTHSERVER_LISTEN_HOST_HTTP="0.0.0.0"
ENV GOIABADA_AUTHSERVER_LISTEN_PORT_HTTP=9090
ENV GOIABADA_AUTHSERVER_CERTFILE=""
ENV GOIABADA_AUTHSERVER_KEYFILE=""
ENV GOIABADA_AUTHSERVER_TRUST_PROXY_HEADERS="false"
ENV GOIABADA_AUTHSERVER_RATELIMITER_ENABLED="false"
ENV GOIABADA_AUTHSERVER_RATELIMITER_MAXREQUESTS="50"
ENV GOIABADA_AUTHSERVER_RATELIMITER_WINDOWSIZEINSECONDS="10"
ENV GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS="true"
ENV GOIABADA_AUTHSERVER_LOG_SQL="false"
ENV GOIABADA_AUTHSERVER_AUDIT_LOGS_IN_CONSOLE="true"
ENV GOIABADA_AUTHSERVER_STATICDIR=""
ENV GOIABADA_AUTHSERVER_TEMPLATEDIR=""

# mysql
# ENV GOIABADA_DB_TYPE="mysql"
# ENV GOIABADA_DB_USERNAME="root"
# ENV GOIABADA_DB_PASSWORD="abc123"
# ENV GOIABADA_DB_HOST="mysql-server"
# ENV GOIABADA_DB_PORT="3306"
# ENV GOIABADA_DB_NAME="goiabada"

# sqlite
#ENV GOIABADA_DB_TYPE="sqlite"
#ENV GOIABADA_DB_DSN="file:/workspaces/goiabada/goiabada.db?_pragma=busy_timeout=5000&_pragma=journal_mode=WAL"

# postgres
# ENV GOIABADA_DB_TYPE="postgres"
# ENV GOIABADA_DB_USERNAME="postgres"
# ENV GOIABADA_DB_PASSWORD="abc123"
# ENV GOIABADA_DB_HOST="postgres-server"
# ENV GOIABADA_DB_PORT="5432"
# ENV GOIABADA_DB_NAME="goiabada"

# mssql
ENV GOIABADA_DB_TYPE="mssql"
ENV GOIABADA_DB_USERNAME="sa"
ENV GOIABADA_DB_PASSWORD="YourStr0ngPassw0rd!"
ENV GOIABADA_DB_HOST="mssql-server"
ENV GOIABADA_DB_PORT="1433"
ENV GOIABADA_DB_NAME="goiabada"

ENV GOIABADA_DB_DSN="file::memory:?cache=shared"

ENV GOIABADA_ADMINCONSOLE_BASEURL="http://localhost:9091"
ENV GOIABADA_ADMINCONSOLE_INTERNALBASEURL=""
ENV GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTPS="0.0.0.0"
ENV GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTPS=9444
ENV GOIABADA_ADMINCONSOLE_LISTEN_HOST_HTTP="0.0.0.0"
ENV GOIABADA_ADMINCONSOLE_LISTEN_PORT_HTTP=9091
ENV GOIABADA_ADMINCONSOLE_CERTFILE=""
ENV GOIABADA_ADMINCONSOLE_KEYFILE=""
ENV GOIABADA_ADMINCONSOLE_TRUST_PROXY_HEADERS="false"
ENV GOIABADA_ADMINCONSOLE_RATELIMITER_ENABLED="false"
ENV GOIABADA_ADMINCONSOLE_RATELIMITER_MAXREQUESTS="50"
ENV GOIABADA_ADMINCONSOLE_RATELIMITER_WINDOWSIZEINSECONDS="10"
ENV GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS="true"
ENV GOIABADA_ADMINCONSOLE_LOG_SQL="false"
ENV GOIABADA_ADMINCONSOLE_AUDIT_LOGS_IN_CONSOLE="true"
ENV GOIABADA_ADMINCONSOLE_STATICDIR=""
ENV GOIABADA_ADMINCONSOLE_TEMPLATEDIR=""