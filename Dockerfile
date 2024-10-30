ARG GO_VERSION=1.23.2
ARG ALPINE_VERSION=3.20.3
ARG OSV_SCANNER_VERSION=v1.9.0

FROM golang:${GO_VERSION}-alpine as builder
ARG OSV_SCANNER_VERSION

WORKDIR /app

# Install OSV Scanner
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@${OSV_SCANNER_VERSION}

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Build the application
COPY main.go main.go
COPY internal/ internal/
RUN go build -o build/

FROM alpine:${ALPINE_VERSION} as final

WORKDIR /app

COPY --from=builder /go/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=builder /app/build/securityscanner /usr/local/bin/securityscanner
