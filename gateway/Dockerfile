FROM golang:1.23-alpine AS build
WORKDIR /src
# Sibling-module replace: gateway/go.mod points at ../config. Both folders
# must be in the build context, so this Dockerfile builds from the repo
# root (see docker-compose.yml `context: .`). Copy config first so the
# go mod download layer cache survives gateway-only edits.
COPY config ./config
WORKDIR /src/gateway
COPY gateway/go.mod gateway/go.sum ./
RUN go mod download
COPY gateway/*.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/veto-gateway .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/veto-gateway /veto-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/veto-gateway"]
