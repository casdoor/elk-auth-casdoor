FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /elk-auth-casdoor .

FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=build /elk-auth-casdoor /usr/local/bin/elk-auth-casdoor
WORKDIR /app
EXPOSE 8080
ENTRYPOINT ["elk-auth-casdoor", "-config", "/app/conf/config.json"]
