# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

RUN apk update && apk upgrade --no-cache && apk add --no-cache git ca-certificates tzdata

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -o /out/clavex ./cmd/server

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/migrate ./cmd/migrate

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/seed ./cmd/seed

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/clavex /clavex
COPY --from=builder /out/migrate /migrate
COPY --from=builder /out/seed /seed

EXPOSE 8080

ENTRYPOINT ["/clavex"]
