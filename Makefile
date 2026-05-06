BIN     := bin/ipunt1
SRC     := $(shell find . -name '*.go') web/index.html
HOST    ?= on1
REMOTE_BIN := /usr/local/bin/ipunt1
LDFLAGS := -s -w

.PHONY: all build run dev test fmt vet linux deploy install-systemd reload-caddy clean

all: build

build: $(BIN)

$(BIN): $(SRC)
	mkdir -p bin
	go build -ldflags="$(LDFLAGS)" -o $(BIN) .

run: build
	IPUNT1_TRUST_CF=false ./$(BIN) -addr 127.0.0.1:8080

dev:
	IPUNT1_TRUST_CF=false IPUNT1_DISABLE_VPN=true go run . -addr 127.0.0.1:8080

test:
	go test ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

# Cross-compile for on1 (linux/amd64).
linux:
	mkdir -p dist
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/ipunt1-linux-amd64 .

# scp + restart on $(HOST). Caddy keeps serving while we swap.
deploy: linux
	scp dist/ipunt1-linux-amd64 $(HOST):/tmp/ipunt1.new
	ssh $(HOST) 'sudo install -m 0755 /tmp/ipunt1.new $(REMOTE_BIN) && sudo systemctl restart ipunt1 && rm /tmp/ipunt1.new && systemctl --no-pager status ipunt1 | head -8'

install-systemd:
	scp deploy/ipunt1.service $(HOST):/tmp/ipunt1.service
	ssh $(HOST) 'sudo install -m 0644 /tmp/ipunt1.service /etc/systemd/system/ipunt1.service && sudo systemctl daemon-reload && sudo systemctl enable ipunt1 && rm /tmp/ipunt1.service'

reload-caddy:
	ssh $(HOST) 'sudo caddy validate --config /etc/caddy/Caddyfile && sudo systemctl reload caddy'

clean:
	rm -rf bin dist
