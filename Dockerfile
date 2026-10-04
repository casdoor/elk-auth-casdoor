FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /elk-auth-casdoor .

FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=build /elk-auth-casdoor /usr/local/bin/elk-auth-casdoor
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["elk-auth-casdoor", "-config", "/app/conf/config.json"]
