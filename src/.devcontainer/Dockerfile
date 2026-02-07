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

# Install yq for YAML parsing (used by version-manager.sh)
RUN curl -sfL --retry 3 --retry-delay 5 https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -o /usr/local/bin/yq && \
    chmod +x /usr/local/bin/yq
RUN rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.25.6.linux-amd64.tar.gz -O /tmp/go1.25.6.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf /tmp/go1.25.6.linux-amd64.tar.gz
RUN rm -f /tmp/go1.25.6.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Install Go development tools to system-wide location
# IMPORTANT: We install tools to /usr/local/go-tools (root-owned) to make them available
# to all users, but we DON'T set GOPATH globally. This allows project builds to use the
# default per-user GOPATH (~/go) which is writable by the vscode user.
# The GOPATH is set temporarily for each install command only.
RUN GOPATH=/usr/local/go-tools /usr/local/go/bin/go install -v github.com/air-verse/air@latest && \
    GOPATH=/usr/local/go-tools /usr/local/go/bin/go install -v golang.org/x/tools/gopls@latest && \
    GOPATH=/usr/local/go-tools /usr/local/go/bin/go install -v github.com/go-delve/delve/cmd/dlv@latest && \
    GOPATH=/usr/local/go-tools /usr/local/go/bin/go install -v golang.org/x/tools/cmd/goimports@latest && \
    GOPATH=/usr/local/go-tools /usr/local/go/bin/go install -v honnef.co/go/tools/cmd/staticcheck@latest && \
    GOPATH=/usr/local/go-tools /usr/local/go/bin/go install -v github.com/cweill/gotests/gotests@latest && \
    GOPATH=/usr/local/go-tools /usr/local/go/bin/go install -v github.com/go-critic/go-critic/cmd/gocritic@latest && \
    GOPATH=/usr/local/go-tools /usr/local/go/bin/go install -v mvdan.cc/unparam@latest && \
    GOPATH=/usr/local/go-tools /usr/local/go/bin/go install -v github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.8.0 && \
    GOPATH=/usr/local/go-tools /usr/local/go/bin/go install -v github.com/vektra/mockery/v3@v3.6.3

# Add Go tools bin directory to PATH (tools are accessible but don't affect project GOPATH)
ENV PATH="/usr/local/go-tools/bin:${PATH}"

# Install Tailwind CLI tool
RUN curl -sfLO --retry 3 --retry-delay 5 https://github.com/tailwindlabs/tailwindcss/releases/download/v4.1.18/tailwindcss-linux-x64
RUN chmod +x tailwindcss-linux-x64
RUN mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss

# Install Node.js and npm (for test-integrations/react-vite)
RUN curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
RUN apt-get install -y nodejs
RUN rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/lib/sqlite

# Create vscode user with sudo access
# Use USER_UID/USER_GID args to match host user for proper file permissions
# If UID/GID already exists, reuse it by renaming the existing user/group
RUN EXISTING_GROUP=$(getent group ${USER_GID} | cut -d: -f1 || echo "") && \
    EXISTING_USER=$(getent passwd ${USER_UID} | cut -d: -f1 || echo "") && \
    if [ -n "$EXISTING_GROUP" ] && [ "$EXISTING_GROUP" != "${USERNAME}" ]; then \
        groupmod -n ${USERNAME} $EXISTING_GROUP; \
    elif [ -z "$EXISTING_GROUP" ]; then \
        groupadd --gid ${USER_GID} ${USERNAME}; \
    fi && \
    if [ -n "$EXISTING_USER" ] && [ "$EXISTING_USER" != "${USERNAME}" ]; then \
        usermod -l ${USERNAME} -d /home/${USERNAME} -m $EXISTING_USER; \
    elif [ -z "$EXISTING_USER" ]; then \
        useradd --uid ${USER_UID} --gid ${USER_GID} -m ${USERNAME} -s /bin/bash; \
    fi && \
    usermod -aG sudo ${USERNAME} && \
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME} && \
    chmod 0440 /etc/sudoers.d/${USERNAME} && \
    mkdir -p /workspaces && \
    chown -R ${USERNAME}:${USERNAME} /workspaces

# Configure bash prompt for vscode user
RUN echo 'export PS1="\[\e[01;32m\]\u@\h\[\e[00m\]:\[\e[01;34m\]\w\[\e[00m\]\$ "' >> /home/${USERNAME}/.bashrc && \
    chown ${USERNAME}:${USERNAME} /home/${USERNAME}/.bashrc
