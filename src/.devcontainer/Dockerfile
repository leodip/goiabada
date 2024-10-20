FROM fedora:latest

# Some basic utils
RUN dnf -y update
RUN dnf -y install curl wget nano make git gh ripgrep openssl python3 python3-pip

RUN pip install mkdocs mkdocs-material

# Go
RUN wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz -O /tmp/go1.23.2.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.23.2.linux-amd64.tar.gz
RUN rm -f /tmp/go1.23.2.linux-amd64.tar.gz
RUN echo "export PATH=$PATH:/usr/local/go/bin:/root/go/bin" >> ~/.bashrc

# Golang Air
RUN /usr/local/go/bin/go install -v github.com/air-verse/air@latest

# Go tools
RUN /usr/local/go/bin/go install -v golang.org/x/tools/gopls@latest
RUN /usr/local/go/bin/go install -v github.com/go-delve/delve/cmd/dlv@latest
RUN /usr/local/go/bin/go install -v golang.org/x/tools/cmd/goimports@latest
RUN /usr/local/go/bin/go install -v honnef.co/go/tools/cmd/staticcheck@latest
RUN /usr/local/go/bin/go install -v github.com/cweill/gotests/gotests@latest
RUN /usr/local/go/bin/go install -v github.com/go-critic/go-critic/cmd/gocritic@latest
RUN /usr/local/go/bin/go install -v mvdan.cc/unparam@latest
RUN /usr/local/go/bin/go install -v github.com/go-critic/go-critic/cmd/gocritic@latest
RUN /usr/local/go/bin/go install -v github.com/golangci/golangci-lint/cmd/golangci-lint@v1.61.0
RUN /usr/local/go/bin/go install -v github.com/vektra/mockery/v2@v2.46.3

# Tailwind CLI tool
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.14/tailwindcss-linux-x64
RUN chmod +x tailwindcss-linux-x64
RUN mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss

RUN mkdir -p /var/lib/sqlite

# Environment variables (config) ------------------------

ENV TZ="Europe/Lisbon"

ENV GOIABADA_AUTHSERVER_ADMIN_EMAIL="admin@example.com"
ENV GOIABADA_AUTHSERVER_ADMIN_PASSWORD="changeme"
ENV GOIABADA_AUTHSERVER_APPNAME="Goiabada"

ENV GOIABADA_AUTHSERVER_BASEURL="http://localhost:8080"
ENV GOIABADA_AUTHSERVER_HOST="0.0.0.0"
ENV GOIABADA_AUTHSERVER_PORT="8080"
ENV GOIABADA_AUTHSERVER_CERTFILE=""
ENV GOIABADA_AUTHSERVER_KEYFILE=""
ENV GOIABADA_AUTHSERVER_ISBEHINDAREVERSEPROXY="false"
ENV GOIABADA_AUTHSERVER_RATELIMITER_ENABLED="false"
ENV GOIABADA_AUTHSERVER_RATELIMITER_MAXREQUESTS="50"
ENV GOIABADA_AUTHSERVER_RATELIMITER_WINDOWSIZEINSECONDS="10"
ENV GOIABADA_AUTHSERVER_LOG_HTTP_REQUESTS="true"
ENV GOIABADA_AUTHSERVER_LOG_SQL="false"
ENV GOIABADA_AUTHSERVER_AUDIT_LOGS_IN_CONSOLE="true"
ENV GOIABADA_AUTHSERVER_STATICDIR=""
ENV GOIABADA_AUTHSERVER_TEMPLATEDIR=""

# mysql
ENV GOIABADA_DB_TYPE="mysql"
ENV GOIABADA_DB_USERNAME="root"
ENV GOIABADA_DB_PASSWORD="abc123"
ENV GOIABADA_DB_HOST="mysql-server"
ENV GOIABADA_DB_PORT="3306"
ENV GOIABADA_DB_NAME="goiabada"
# sqlite
#ENV GOIABADA_DB_TYPE="sqlite"
#ENV GOIABADA_DB_DSN="file:/workspaces/goiabada/goiabada.db?_pragma=busy_timeout=5000&_pragma=journal_mode=WAL"
ENV GOIABADA_DB_DSN="file::memory:?cache=shared"

ENV GOIABADA_ADMINCONSOLE_BASEURL="http://localhost:8081"
ENV GOIABADA_ADMINCONSOLE_HOST="0.0.0.0"
ENV GOIABADA_ADMINCONSOLE_PORT="8081"
ENV GOIABADA_ADMINCONSOLE_CERTFILE=""
ENV GOIABADA_ADMINCONSOLE_KEYFILE=""
ENV GOIABADA_ADMINCONSOLE_ISBEHINDAREVERSEPROXY="false"
ENV GOIABADA_ADMINCONSOLE_RATELIMITER_ENABLED="false"
ENV GOIABADA_ADMINCONSOLE_RATELIMITER_MAXREQUESTS="50"
ENV GOIABADA_ADMINCONSOLE_RATELIMITER_WINDOWSIZEINSECONDS="10"
ENV GOIABADA_ADMINCONSOLE_LOG_HTTP_REQUESTS="true"
ENV GOIABADA_ADMINCONSOLE_LOG_SQL="false"
ENV GOIABADA_ADMINCONSOLE_AUDIT_LOGS_IN_CONSOLE="true"
ENV GOIABADA_ADMINCONSOLE_STATICDIR=""
ENV GOIABADA_ADMINCONSOLE_TEMPLATEDIR=""
