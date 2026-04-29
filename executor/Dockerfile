FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod .
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /executor .

FROM alpine:3.20
RUN apk add --no-cache bash coreutils curl jq
COPY --from=build /executor /executor
RUN mkdir -p /workspace /run/execsock \
    && chown 1000:1000 /workspace /run/execsock
VOLUME /run/execsock
WORKDIR /workspace
CMD ["/executor"]
