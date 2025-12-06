FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update

RUN apt-get install -y iputils-ping
RUN apt-get install -y lsof
RUN apt-get install -y net-tools
RUN apt-get install -y iproute2
RUN apt-get install -y curl
RUN apt-get install -y wget
RUN apt-get install -y nano
RUN apt-get install -y make
RUN apt-get install -y git
RUN apt-get install -y zip
RUN apt-get install -y ripgrep
RUN apt-get install -y openssl
RUN rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.25.4.linux-amd64.tar.gz -O /tmp/go1.25.4.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.25.4.linux-amd64.tar.gz
RUN rm -f /tmp/go1.25.4.linux-amd64.tar.gz
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
RUN /usr/local/go/bin/go install -v github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.6.2
RUN /usr/local/go/bin/go install -v github.com/vektra/mockery/v3@v3.6.1

# Install Tailwind CLI tool
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v4.1.17/tailwindcss-linux-x64
RUN chmod +x tailwindcss-linux-x64
RUN mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss

RUN mkdir -p /var/lib/sqlite
