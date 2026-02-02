FROM golang:1.23-alpine3.20 AS builder
RUN apk update && apk add --no-cache openssh-keygen build-base
WORKDIR /build
RUN ssh-keygen -f ./id_rsa -N ""

COPY go.mod go.sum .
RUN go mod download

COPY main.go .
RUN CGO_ENABLED=1 go build -o server main.go

FROM alpine:3.20
WORKDIR /project

COPY --from=builder /build/server .
COPY --from=builder /build/id_rsa .
COPY --from=builder /build/id_rsa.pub .

CMD ["./server", "fakeshell", "-p", "22", "-C"]

EXPOSE 22
