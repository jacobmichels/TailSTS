FROM golang:1.24.1-alpine3.20@sha256:3d9132b88a6317b846b55aa8e821821301906fe799932ecbc4f814468c6977a5 AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o /usr/bin/server cmd/server/main.go

FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

COPY --from=builder /usr/bin/server /usr/bin/server

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

ENTRYPOINT [ "/usr/bin/server" ]
