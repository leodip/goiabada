FROM fedora:latest

# Some basic utils
RUN dnf -y update
RUN dnf -y install curl wget nano make git ripgrep

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

# Tailwind CLI tool
RUN curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/download/v3.3.5/tailwindcss-linux-x64
RUN chmod +x tailwindcss-linux-x64
RUN mv tailwindcss-linux-x64 /usr/local/bin/tailwindcss