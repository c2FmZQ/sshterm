FROM golang:1.27.3-alpine3.24 AS build
RUN apk update && apk upgrade
RUN apk add ca-certificates

ADD . /app/go/src/sshterm
WORKDIR /app/go/src/sshterm
RUN if [ ! -f go/sshterm-server/internal/docroot/ssh.wasm ]; then apk add bash npm && ./build.sh; fi
WORKDIR /app/go/src/sshterm/go
RUN go mod download
RUN source ../version.sh && CGO_ENABLED=0 go install -ldflags="-s -w -X main.Version=${VERSION:-dev}" ./sshterm-server

FROM scratch
WORKDIR /
COPY --from=build /etc/ssl /etc/ssl/
COPY --from=build /usr/share/ca-certificates /usr/share/ca-certificates/
COPY --from=build /go/bin/sshterm-server /bin/

EXPOSE 8080
USER 1000:1000
ENV GODEBUG="clobberfree=1,http2xconnect=0"

ENTRYPOINT ["/bin/sshterm-server", "--addr=:8080"]
