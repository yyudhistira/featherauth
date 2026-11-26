# FeatherAuth image. Build from the repository root:
#   docker build -f deploy/Dockerfile -t featherauth .
# Base images are pinned by tag and digest, so a rebuild cannot change them
# silently. To update, pull the new tag and replace the digest.
FROM golang:1.27.4@sha256:5e8afd493a7124a8586e134d9b532731161d4b9becf9dee5a5956b107426f93d AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/featherauth ./cmd/featherauth
# Empty data and backup directories owned by the non-root user, so that new
# named volumes mounted there are writable.
RUN mkdir -p /out/var/lib/featherauth /out/var/backups/featherauth

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/featherauth /featherauth
COPY --from=build --chown=65532:65532 /out/var /var
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=6 \
  CMD ["/featherauth", "healthcheck"]
ENTRYPOINT ["/featherauth"]
CMD ["serve"]
