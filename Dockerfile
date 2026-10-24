ARG BUILDPLATFORM

# The web UI is platform independent; build it once on the build host.
FROM --platform=$BUILDPLATFORM node:25-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY --from=web /src/internal/web/dist/app/ internal/web/dist/app/
ARG TARGETOS TARGETARCH VERSION=dev COMMIT=none
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags "-s -w -X github.com/mnorrsken/trivyal/internal/version.Version=${VERSION} -X github.com/mnorrsken/trivyal/internal/version.Commit=${COMMIT}" \
    -o /out/trivyal ./cmd/trivyal

# distroless: no shell or package manager, so the image trivyal shows
# in its own reports stays small.
FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/trivyal /trivyal
USER 65532:65532
EXPOSE 8080 9090
ENTRYPOINT ["/trivyal"]
