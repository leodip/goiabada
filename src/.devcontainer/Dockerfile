FROM ubuntu:latest

ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000

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
RUN apt-get install -y sudo
RUN rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.25.6.linux-amd64.tar.gz -O /tmp/go1.25.6.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.25.6.linux-amd64.tar.gz
RUN rm -f /tmp/go1.25.6.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:/home/${USERNAME}/go/bin:${PATH}"

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
RUN /usr/local/go/bin/go install -v github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.8.0
RUN /usr/local/go/bin/go install -v github.com/vektra/mockery/v3@v3.6.3

# Install Tailwind CLI tool
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v4.1.18/tailwindcss-linux-x64
RUN chmod +x tailwindcss-linux-x64
RUN mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss

# Install Node.js and npm (for test-integrations/react-vite)
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
RUN apt-get install -y nodejs
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/lib/sqlite

# Align container user/group with host UID/GID to avoid permission issues on mounted volumes.
RUN existing_user="$(getent passwd ${USER_UID} | cut -d: -f1)" \
    && existing_group="$(getent group ${USER_GID} | cut -d: -f1)" \
    && if [ -z "${existing_group}" ]; then groupadd --gid ${USER_GID} ${USERNAME}; \
       elif [ "${existing_group}" != "${USERNAME}" ]; then groupmod -n ${USERNAME} ${existing_group}; fi \
    && if [ -z "${existing_user}" ]; then useradd --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME}; \
       elif [ "${existing_user}" != "${USERNAME}" ]; then usermod -l ${USERNAME} ${existing_user} \
       && usermod -d /home/${USERNAME} -m ${USERNAME}; fi \
    && usermod -aG sudo ${USERNAME} \
    && echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} \
    && chmod 0440 /etc/sudoers.d/${USERNAME} \
    && mkdir -p /workspaces \
    && chown -R ${USERNAME}:${USERNAME} /workspaces
