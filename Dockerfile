FROM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS go-source
WORKDIR /src
ENV GOTOOLCHAIN=local GOWORK=off GOTELEMETRY=off
COPY go.mod go.sum ./
# Network access is confined to development dependency preparation. Later Go
# build/test stages reuse this verified cache with module downloads disabled.
RUN go mod download && go mod verify
ENV GOPROXY=off GOSUMDB=off GOPRIVATE= GONOPROXY= GONOSUMDB= GOFLAGS=-mod=readonly
COPY cmd/ cmd/
COPY internal/ internal/
COPY scripts/check-go-format.sh scripts/check-go-format.sh

FROM go-source AS check-go
RUN bash scripts/check-go-format.sh && go vet ./cmd/... ./internal/... && go test -race ./cmd/... ./internal/...

FROM go-source AS build-go
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/andeiva ./cmd/andeiva \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/andeiva-api ./cmd/andeiva-api

FROM node:24.20.0-trixie-slim@sha256:50c3b2f6988dfc307b86e5301d69611af31f4789bdf232863b07d3b02fe55ae0 AS check-web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/tsconfig.json frontend/tsconfig.test.json frontend/eslint.config.mjs frontend/index.html ./
COPY frontend/src/ src/
COPY frontend/public/andeiva-logo.png public/andeiva-logo.png
COPY frontend/public/theme-init.js public/theme-init.js
COPY frontend/tests/ tests/
COPY frontend/scripts/ scripts/
RUN npm run lint && npm run typecheck && npm test && npm run build \
    && cmp public/andeiva-logo.png dist/andeiva-logo.png

# Development smoke target, not an appliance OS image.
FROM scratch AS api
COPY --from=build-go /out/andeiva /andeiva
COPY --from=build-go /out/andeiva-api /andeiva-api
COPY LICENSE NOTICE /licenses/
COPY packaging/licenses/golang-x-LICENSE.txt packaging/licenses/golang-x-PATENTS.txt /licenses/
COPY --from=build-go /usr/local/go/LICENSE /licenses/GO-LICENSE
USER 65532:65532
ENV ANDEIVA_LISTEN_ADDR=0.0.0.0:4000
EXPOSE 4000
HEALTHCHECK --interval=5s --timeout=2s --start-period=2s --retries=3 CMD ["/andeiva-api", "--healthcheck"]
ENTRYPOINT ["/andeiva-api"]
