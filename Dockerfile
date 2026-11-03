# UnifiedGuard — image de la centrale (hub) — BETA
# Build:  docker build -t unifiedguard/hub:beta .
# Deux étages : builder Go (source complète) → runtime minimal (binaire seul).
# Le binaire embarque : UI (go:embed), migrations (go:embed), serveur.

# ---------- builder ----------
FROM golang:1.24-bookworm AS builder
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
# deps d'abord (cache Docker par couche)
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG COMMIT=dev
ARG DATE=unknown
RUN go build -ldflags "-s -w \
      -X git.dpnac.cloud/dpnac/central/internal/version.gitCommit=${COMMIT} \
      -X git.dpnac.cloud/dpnac/central/internal/version.buildDate=${DATE}" \
    -o /out/hub ./cmd/hub \
 && go build -ldflags "-s -w \
      -X git.dpnac.cloud/dpnac/central/internal/version.gitCommit=${COMMIT} \
      -X git.dpnac.cloud/dpnac/central/internal/version.buildDate=${DATE}" \
    -o /out/agent ./cmd/agent \
 && go build -ldflags "-s -w \
      -X git.dpnac.cloud/dpnac/central/internal/version.gitCommit=${COMMIT} \
      -X git.dpnac.cloud/dpnac/central/internal/version.buildDate=${DATE}" \
    -o /out/fleet ./cmd/fleet

# ---------- hub runtime ----------
FROM debian:bookworm-slim AS hub
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl nftables iptables iproute2 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /out/hub /app/hub
# Volumes : CA (identités agents), clé de site (backups §6.3), TLS.
VOLUME ["/data"]
ENV HUB_LISTEN=:8080 \
    HUB_CA_DIR=/data/ca \
    HUB_SITE_KEY_DIR=/data/sitekey \
    HUB_DATABASE=postgres://unifiedguard:unifiedguard@db:5432/unifiedguard?sslmode=disable \
    HUB_MIGRATIONS=on \
    HUB_MFA_LOG_BETA=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl -fsS http://127.0.0.1:8080/api/v1/ping || exit 1
ENTRYPOINT ["/app/hub"]

# ---------- agent runtime (même build, cible séparée) ----------
FROM debian:bookworm-slim AS agent
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates nftables iptables iproute2 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /out/agent /app/agent
# L'agent doit voir le pare-feu de son HÔTE (pas du conteneur) : en bêta
# l'agent conteneurisé ne gère pas le pare-feu (commit-confirm inactif sur
# l'agent docker) ; l'installation natif est la voie recommandée.
VOLUME ["/data"]
ENV AGENT_STATE_DIR=/data
ENTRYPOINT ["/app/agent"]

# ---------- fleet (console SaaS — squelette J0) ----------
FROM debian:bookworm-slim AS fleet
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /out/fleet /app/fleet
ENV FLEET_LISTEN=:8081
EXPOSE 8081
ENTRYPOINT ["/app/fleet"]