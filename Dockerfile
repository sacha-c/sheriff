ARG GO_VERSION=1.23.2
FROM golang:${GO_VERSION}-alpine as base

WORKDIR /app

FROM base as builder

COPY go.mod go.sum main.go ./
COPY internal/ internal/

RUN go mod download && go mod verify && \
    go build -o build/


FROM base as final

RUN apk add --no-cache osv-scanner

WORKDIR /app

COPY --from=builder /app/build/securityscanner /usr/local/bin/securityscanner
