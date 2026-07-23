# syntax=docker/dockerfile:1

# --- build stage ---
FROM golang:1.26-alpine AS build
WORKDIR /src
# Stdlib-only: no go.sum, nothing to download.
COPY go.mod ./
COPY . .
# Pure-Go, statically linked, stripped.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cms-auth .

# --- runtime stage ---
# distroless/static: no shell, CA certs included (outbound TLS to github.com),
# runs as nonroot by default. Deployments may override the uid at compose level.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cms-auth /app
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
