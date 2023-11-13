FROM fedora:latest

# Some basic utils
RUN dnf -y update
RUN dnf -y install curl wget nano make git gh ripgrep

# Go
RUN wget https://go.dev/dl/go1.21.4.linux-amd64.tar.gz -O /tmp/go1.21.4.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.21.4.linux-amd64.tar.gz
RUN rm -f /tmp/go1.21.4.linux-amd64.tar.gz
RUN echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc

# Golang Air
RUN /usr/local/go/bin/go install -v github.com/cosmtrek/air@latest

# Go tools
RUN /usr/local/go/bin/go install -v golang.org/x/tools/gopls@latest
RUN /usr/local/go/bin/go install -v github.com/go-delve/delve/cmd/dlv@latest
RUN /usr/local/go/bin/go install -v golang.org/x/tools/cmd/goimports@latest
RUN /usr/local/go/bin/go install -v honnef.co/go/tools/cmd/staticcheck@latest
RUN /usr/local/go/bin/go install -v github.com/cweill/gotests/gotests@v1.6.0

# Tailwind CLI tool
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v3.3.5/tailwindcss-linux-x64
RUN chmod +x tailwindcss-linux-x64
RUN mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss

# Environment variables (config) ------------------------

ENV GOIABADA_ADMIN_EMAIL="admin@example.com"
ENV GOIABADA_ADMIN_PASSWORD="admin123"
ENV GOIABADA_APPNAME="Goiabada"
ENV GOIABADA_ISSUER="https://goiabada.local:8080"
ENV GOIABADA_BASEURL="https://goiabada.local:8080"
ENV GOIABADA_PORT="8080"
ENV GOIABADA_TEMPLATEDIR="./web/template"
ENV GOIABADA_STATICDIR="./web/static"
ENV GOIABADA_CERTFILE="../cert/self_signed.crt"
ENV GOIABADA_KEYFILE="../cert/self_signed.key"
ENV GOIABADA_ISBEHINDAREVERSEPROXY="false"
ENV GOIABADA_DB_HOST="mysql-server"
ENV GOIABADA_DB_PORT="3306"
ENV GOIABADA_DB_DBNAME="goiabada"
ENV GOIABADA_DB_USERNAME="root"
ENV GOIABADA_DB_PASSWORD="abc123"

# GORM (sql) log level: Silent, Error, Warn, Info
ENV GOIABADA_LOGGER_GORM_LOGLEVEL="Warn"

# Http requests logging: true, false
ENV GOIABADA_LOGGER_ROUTER_HTTPREQUESTS_ENABLED="true"

# -------------------------------------------------------