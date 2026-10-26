PKG     := github.com/mnorrsken/trivyal
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT)
IMAGE   ?= ghcr.io/mnorrsken/trivyal
# Same Trivy version as the workflows.
TRIVY   ?= aquasec/trivy:0.76.1
WEB_OUT := internal/web/dist/app

# Words that must never appear in the repo (real cluster names), checked in
# tracked and new files. Kept
# outside the repo on purpose; the check is skipped when the file is missing.
LEAK_DENYLIST ?= $(HOME)/.config/trivyal/leak-denylist

.PHONY: all build build-go run dev web web-deps test go-test web-test race vet fmt lint vuln leakcheck helm-lint clean docker-build scan lab lab-down

all: build

web-deps:
	cd web && npm ci

web: web/node_modules
	cd web && npm run build

web/node_modules:
	cd web && npm ci

build: web
	go build -ldflags '$(LDFLAGS)' -o bin/trivyal ./cmd/trivyal

# Backend only, without rebuilding the UI.
build-go:
	go build -ldflags '$(LDFLAGS)' -o bin/trivyal ./cmd/trivyal

run: build
	./bin/trivyal

# Backend against the current kubeconfig plus the Vite dev server with hot
# reload on http://localhost:5173 (proxies /api to the backend). Hidden
# items are kept in bin/trivyal.db.
dev: build-go
	@trap 'kill 0' EXIT; ./bin/trivyal -listen 127.0.0.1:8080 -metrics-listen 127.0.0.1:9090 -database-url sqlite:bin/trivyal.db & cd web && npm run dev

test: go-test web-test

go-test:
	go test ./...

web-test: web/node_modules
	cd web && npm run check && npm test

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

lint:
	golangci-lint run

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

leakcheck:
	@if [ -s "$(LEAK_DENYLIST)" ]; then \
		if git ls-files -z -co --exclude-standard | xargs -0 grep -n -i -w -F -f "$(LEAK_DENYLIST)" -- 2>/dev/null; then \
			echo "leakcheck: cluster-specific names found (see above)"; exit 1; \
		else echo "leakcheck: ok"; fi; \
	else echo "leakcheck: no denylist at $(LEAK_DENYLIST), skipped"; fi

helm-lint:
	helm lint charts/trivyal
	helm template charts/trivyal | kubectl apply --dry-run=client -f - >/dev/null

clean:
	rm -rf bin dist $(WEB_OUT) web/.svelte-kit

docker-build:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE):$(VERSION) .

# Trivy, as in CI: the source tree (dependencies, secrets) and a fresh
# image. Fails on any vulnerability that has a fix.
scan:
	docker build -q -t trivyal:scan . >/dev/null
	docker run --rm -v $(HOME)/.cache/trivy:/root/.cache/trivy -v $(CURDIR):/src:ro $(TRIVY) fs --quiet \
		--scanners vuln,secret --ignore-unfixed --exit-code 1 --skip-dirs web/node_modules,bin,internal/web/dist /src
	docker run --rm -v $(HOME)/.cache/trivy:/root/.cache/trivy -v /var/run/docker.sock:/var/run/docker.sock $(TRIVY) image --quiet \
		--scanners vuln --ignore-unfixed --exit-code 1 trivyal:scan

# Throwaway kind cluster with trivy-operator and this build (dev/lab.sh).
lab:
	dev/lab.sh up

lab-down:
	dev/lab.sh down
