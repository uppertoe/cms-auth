# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183

# --- build stage ---
FROM golang:1.27-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS build
WORKDIR /src
# Stdlib-only: no go.sum, nothing to download.
COPY go.mod ./
COPY . .
# Pure-Go, statically linked, stripped.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cms-auth .

# --- runtime stage ---
# distroless/static: no shell, CA certs included (outbound TLS to github.com),
# runs as nonroot by default. Deployments may override the uid at compose level.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/cms-auth /app
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
