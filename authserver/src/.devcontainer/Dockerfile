FROM fedora:latest

# Some basic utils
RUN dnf -y update
RUN dnf -y install curl wget nano make git gh ripgrep openssl

# Go
RUN wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go1.22.0.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.22.0.linux-amd64.tar.gz
RUN rm -f /tmp/go1.22.0.linux-amd64.tar.gz
RUN echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc

# Golang Air
RUN /usr/local/go/bin/go install -v github.com/cosmtrek/air@latest

# Go tools
RUN /usr/local/go/bin/go install -v golang.org/x/tools/gopls@latest
RUN /usr/local/go/bin/go install -v github.com/go-delve/delve/cmd/dlv@latest
RUN /usr/local/go/bin/go install -v golang.org/x/tools/cmd/goimports@latest
RUN /usr/local/go/bin/go install -v honnef.co/go/tools/cmd/staticcheck@latest
RUN /usr/local/go/bin/go install -v github.com/cweill/gotests/gotests@latest
RUN /usr/local/go/bin/go install -v github.com/go-critic/go-critic/cmd/gocritic@latest

# Tailwind CLI tool
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v3.4.1/tailwindcss-linux-x64
RUN chmod +x tailwindcss-linux-x64
RUN mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss

# Environment variables (config) ------------------------

ENV TZ="Europe/Lisbon"
ENV GOIABADA_ADMIN_EMAIL="admin@example.com"
ENV GOIABADA_ADMIN_PASSWORD="changeme"
ENV GOIABADA_APPNAME="Goiabada"
ENV GOIABADA_HOST=
ENV GOIABADA_PORT="8080"
ENV GOIABADA_TEMPLATEDIR="./web/template"
ENV GOIABADA_STATICDIR="./web/static"
ENV GOIABADA_ISBEHINDAREVERSEPROXY="false"
ENV GOIABADA_RATELIMITER_ENABLED="false"

ENV GOIABADA_DB_TYPE="sqlite"
# only for sqlite3
ENV GOIABADA_DB_DSN="file:/workspaces/goiabada/goiabada.db?_pragma=busy_timeout=5000&_pragma=journal_mode=WAL"
# ENV GOIABADA_DB_HOST="mysql-server"
# ENV GOIABADA_DB_PORT="3306"
# ENV GOIABADA_DB_DBNAME="goiabada"
# ENV GOIABADA_DB_USERNAME="root"
# ENV GOIABADA_DB_PASSWORD="abc123"

# With TLS (https)
# ENV GOIABADA_ISSUER="https://localhost:8080"
# ENV GOIABADA_BASEURL="https://localhost:8080"
# ENV GOIABADA_CERTFILE="../cert/self_signed_cert.pem"
# ENV GOIABADA_KEYFILE="../cert/self_signed_key.pem"

# Without TLS (http) - do not use in production!
ENV GOIABADA_ISSUER="http://localhost:8080"
ENV GOIABADA_BASEURL="http://localhost:8080"
ENV GOIABADA_CERTFILE=
ENV GOIABADA_KEYFILE=

ENV GOIABADA_LOG_SQL="false"

# Http requests logging: true, false
ENV GOIABADA_LOGGER_ROUTER_HTTPREQUESTS_ENABLED="true"

ENV GOIABADA_AUDITING_CONSOLELOG_ENABLED="true"

# -------------------------------------------------------