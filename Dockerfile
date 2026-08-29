# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X github.com/Hortlund/tunnl/internal/version.Version=${VERSION} -X github.com/Hortlund/tunnl/internal/version.Commit=${COMMIT} -X github.com/Hortlund/tunnl/internal/version.Date=${BUILD_DATE}" \
    -o /out/tunnld ./cmd/tunnld
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tunnld /usr/local/bin/tunnld
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080/tcp 8443/tcp 8443/udp
ENV TUNNL_DATABASE=/data/tunnl.db
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/tunnld", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/tunnld"]
