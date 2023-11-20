FROM golang:1.21.4-alpine AS buildStage

WORKDIR /app/src

COPY ./src/go.mod ./

RUN go mod download

COPY ./src ./

RUN mkdir -p /app/bin
RUN go build -o ../bin/goiabada ./cmd/goiabada/main.go

# ------------------------------------------------------------------------------

FROM alpine:latest AS final

WORKDIR /app

RUN apk add --no-cache tzdata alpine-conf
RUN /sbin/setup-timezone -z Europe/Lisbon

COPY --from=buildStage /app/bin/goiabada ./
COPY ./src/web ./web
COPY ./cert ./cert
EXPOSE 443/tcp

ENTRYPOINT ["/app/goiabada"]