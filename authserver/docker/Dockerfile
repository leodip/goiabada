FROM golang:1.21-alpine AS buildStage

WORKDIR /app/src

COPY ./src/go.mod ./

RUN go mod download

COPY ./src ./

RUN mkdir -p /app/bin
RUN go build -o ../bin/goiabada ./cmd/goiabada/main.go

# ------------------------------------------------------------------------------

FROM golang:1.21-alpine AS final

WORKDIR /app

COPY --from=buildStage /app/bin/goiabada ./
COPY ./src/web/static ./static
COPY ./src/web/template ./template

EXPOSE 5000

ENTRYPOINT ["/app/goiabada"]