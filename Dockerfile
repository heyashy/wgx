FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/wgx .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends wireguard-tools iproute2 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/wgx /usr/local/bin/wgx
RUN mkdir -p /etc/wireguard && chmod 700 /etc/wireguard
WORKDIR /etc/wireguard
CMD ["sleep", "infinity"]
