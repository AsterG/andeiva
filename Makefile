.PHONY: web-install lint test build smoke containers

web-install:
	npm --prefix frontend ci --ignore-scripts --no-audit --no-fund

lint:
	node scripts/check-repository.mjs
	bash scripts/check-go-format.sh
	go vet ./cmd/... ./internal/...
	npm --prefix frontend run lint
	npm --prefix frontend run typecheck

test:
	go test -race ./cmd/... ./internal/...
	npm --prefix frontend test

build:
	go build ./cmd/... ./internal/...
	npm --prefix frontend run build

smoke:
	bash scripts/smoke-api.sh

containers:
	docker build --target check-go -t andeiva-go-check .
	docker build --target check-web -t andeiva-web-check .
	docker compose config --quiet
	docker compose up --build --wait --wait-timeout 60
