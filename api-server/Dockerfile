FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod .
COPY main.go .
RUN CGO_ENABLED=0 go build -o /api-server .

FROM alpine:3.20
COPY --from=build /api-server /api-server
CMD ["/api-server"]
