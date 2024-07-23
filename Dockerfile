FROM golang:1.22.5-alpine3.20@sha256:0e90634e2a706a24f1176483f7315e019738d53a188b7a57c1f58426999bb0ee AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o /usr/bin/server cmd/server/main.go

FROM alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5

COPY --from=builder /usr/bin/server /usr/bin/server

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

ENTRYPOINT [ "/usr/bin/server" ]
