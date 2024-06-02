FROM golang:1.22.3-alpine AS buildStage

ARG version
ARG buildDate
ARG gitCommit

WORKDIR /app/src

COPY ./src/go.mod ./

RUN go mod download

COPY ./src ./

RUN mkdir -p /app/bin
RUN go build -ldflags="-X 'github.com/leodip/goiabada/internal/constants.Version=${version}' -X 'github.com/leodip/goiabada/internal/constants.BuildDate=${buildDate}' -X 'github.com/leodip/goiabada/internal/constants.GitCommit=${gitCommit}'" -o ../bin/goiabada ./cmd/goiabada/main.go

# ------------------------------------------------------------------------------

FROM alpine:latest AS final

WORKDIR /app

RUN apk add --no-cache tzdata alpine-conf
RUN /sbin/setup-timezone -z Europe/Lisbon

COPY --from=buildStage /app/bin/goiabada ./
COPY ./src/web ./web
COPY ./cer[t] ./cert
EXPOSE 80/tcp
EXPOSE 443/tcp

ENTRYPOINT ["/app/goiabada"]