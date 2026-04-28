FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 go build -o /executor .

FROM alpine:3.20
RUN apk add --no-cache bash coreutils curl jq
COPY --from=build /executor /executor
RUN mkdir -p /workspace
WORKDIR /workspace
CMD ["/executor"]
