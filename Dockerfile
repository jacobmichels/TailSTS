FROM golang:1.23.6-alpine3.20@sha256:22caeb4deced0138cb4ae154db260b22d1b2ef893dde7f84415b619beae90901 AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o /usr/bin/server cmd/server/main.go

FROM alpine:3.21.2@sha256:56fa17d2a7e7f168a043a2712e63aed1f8543aeafdcee47c58dcffe38ed51099

COPY --from=builder /usr/bin/server /usr/bin/server

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

ENTRYPOINT [ "/usr/bin/server" ]
