FROM golang:1.21.6-alpine3.19 as builder
RUN apk update && apk add --no-cache openssh-keygen build-base
WORKDIR /build
RUN ssh-keygen -f ./id_rsa -N ""

COPY app/main.go .

RUN go mod init ssh-honeypot
RUN go get -u "github.com/gliderlabs/ssh"
RUN go get -u "golang.org/x/crypto/ssh"
RUN go get -u "golang.org/x/crypto/ssh/terminal"
RUN go get -u "github.com/integrii/flaggy"
RUN CGO_ENABLED=1 go get -u "github.com/mattn/go-sqlite3"

RUN CGO_ENABLED=1 go build -o server main.go

FROM alpine:3.19
WORKDIR /project

COPY --from=builder /build/server .
COPY --from=builder /build/id_rsa .
COPY --from=builder /build/id_rsa.pub .

CMD ["./server", "fakeshell", "-p", "22", "-C"]

EXPOSE 22