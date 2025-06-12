#############      builder                                  #############
FROM golang:1.24.4 AS builder

WORKDIR /go/src/github.com/falco-event-provider
COPY . .

RUN mkdir -p bin && \
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO111MODULE=on go build -o "bin/falco-event-provider" cmd/provider/main.go

#############      base                                     #############
FROM gcr.io/distroless/static-debian12:nonroot as base
WORKDIR /

#############     falco-event-provider                      #############
FROM base AS falco-event-provider

COPY --from=builder /go/src/github.com/falco-event-provider/bin/falco-event-provider /falco-event-provider
ENTRYPOINT ["/falco-event-provider"]
