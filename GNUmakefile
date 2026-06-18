# Переменные проекта
VERSION=v1.0.1

WORKDIR=.

MAIN_SERVER=${WORKDIR}/cmd/gophkeeper-server/main.go
BINARY_SERVER=${WORKDIR}/cmd/gophkeeper-server/gophkeeper-server

MAIN_CLIENT=${WORKDIR}/cmd/gophkeeper/main.go
BINARY_CLIENT=${WORKDIR}/cmd/gophkeeper/gophkeeper

# ProtoBuf generator
# Локальные пути для утилит
GOPATH_BIN := $(shell go env GOPATH)/bin
export PATH := $(PATH):$(GOPATH_BIN)

PROTO_DIR := api/proto
GEN_DIR := gen/go


COVER_FILE=coverage.out
DOCKER_IMG=gophkeeper:latest

COMPOSE_FILE=infra/compose.yml

.PHONY: up down logs ps certs clean-certs

## up: Старт сервисов проекта
up:
	docker compose -f $(COMPOSE_FILE) up -d --build

## down: Погасить сервис
down:
	docker compose -f $(COMPOSE_FILE) down

## logs: Вывод логов
logs:
	docker compose -f $(COMPOSE_FILE) logs -f

## ps: Вывод информации о процессах сервиса
ps:
	docker compose -f $(COMPOSE_FILE) ps

## psql: PostgreSQL shell
psql:
	export PGPASSWORD='gophkeeper_pswd' && psql -h localhost -p 5542 -Ugophkeeper -w

keys:
	ssh-keygen -t ed25519 -a 64 -N "" -f ./crypt/gophkeeper_ed25519 -C "gophkeeper"

test:
	go test ./...

test-short:
	go test ./... -short

test-unit:
	go test ./... -short -count=1

test-functional:
	go test -tags=functional ./internal/adapters/sshagent -run Functional -count=1 -v

test-race:
	go test ./... -race -count=1

lint:
	golangci-lint run

build: certs gen-proto
	@echo "Building binary..."
	go generate ./...
	CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.buildVersion=${VERSION} -X main.buildCommit=$$(git log -1 --format='%H') -X main.buildDate=$$(date +%F)" -o $(BINARY_CLIENT) $(MAIN_CLIENT)
	CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.buildVersion=${VERSION} -X main.buildCommit=$$(git log -1 --format='%H') -X main.buildDate=$$(date +%F)" -o $(BINARY_SERVER) $(MAIN_SERVER)

.PHONY: certs
certs:
	@mkdir -p internal/shared/certs/assets
	@mkdir -p .certs_private
	@echo "Generating System Root CAs (v4.0 Isolated PKI)..."
	# 1. Серверный корень (Server CA) для TLS транспорта
	openssl ecparam -name prime256v1 -genkey -noout -out .certs_private/server-ca.key
	openssl req -new -x509 -sha256 -key .certs_private/server-ca.key \
		-days 3650 \
		-subj "/O=GophKeeper Server Network/CN=GophKeeper Server CA" \
		-out internal/shared/certs/assets/server-ca.crt
	# 2. Клиентский корень (Device CA) для строгого mTLS авторизации устройств
	openssl ecparam -name prime256v1 -genkey -noout -out .certs_private/device-ca.key
	openssl req -new -x509 -sha256 -key .certs_private/device-ca.key \
		-days 3650 \
		-subj "/O=GophKeeper Device Trust/CN=GophKeeper Device CA" \
		-out internal/shared/certs/assets/device-ca.crt
	@echo "--------------------------------------------------------"
	@echo "SUCCESS: Public certificates generated in internal/shared/certs/assets/"
	@echo "WARNING: Private keys saved OUTSIDE version control in .certs_private/"
	@echo "Ensure .certs_private/ is added to your .gitignore file!"
	@echo "Pass these key paths to your server via config file or flags."

llm:
	(cat ./go.mod && find ./ -name '*.llm' -exec sh -c 'echo "\n\n"; cat {}' \;) > ./LLM.txt
	find . -type f -name '*.go' -exec sh -c 'echo "# {}"; cat "{}"; echo ""' \; > ./GO.md



.PHONY: gen-proto
gen-proto:
	@echo "Generating Protobuf code..."
	@mkdir -p $(GEN_DIR)
	protoc --proto_path=$(PROTO_DIR) \
		--go_out=$(GEN_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(GEN_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/gophkeeper/v1/*.proto
	@echo "Protobuf artifacts successfully generated in $(GEN_DIR)."

.PHONY: proto-clean
proto-clean:
	@echo "Cleaning generated proto artifacts..."
	@rm -rf $(GEN_DIR)


# ## build: Сборка проекта
# build:
# 	$(MAKE) -C infra/database/accrual build
# 	$(MAKE) -C infra/database/gmart build
# 	$(MAKE) -C infra/accrual build
# 	@echo "Building binary..."
# 	go generate ./...
# 	CGO_ENABLED=0 GOOS=linux go build -o $(BINARY_NAME) $(MAIN_PATH)
# 	@echo "Building scratch Docker image..."
# 	docker build -f Dockerfile -t $(DOCKER_IMG) .
# 
# ## test: Запуск всех тестов с проверкой на Race Condition
# test:
# 	@echo "Running tests with race detector..."
# 	go test -v -race ./...
# 
# ## cover: Проверка покрытия тестами и генерация отчета
# cover:
# 	@echo "Checking test coverage..."
# 	go test -coverprofile=$(COVER_FILE) ./...
# 	go tool cover -func=$(COVER_FILE)
# 	@echo "Generating HTML report..."
# 	go tool cover -html=$(COVER_FILE) -o coverage.html
# 	@echo "Report saved to coverage.html"
# 
# ## bench: Запуск бенчмарков с анализом аллокаций
# bench:
# 	@echo "Running benchmarks..."
# 	go test -bench=. -benchmem ./...
# 
# ## escape: Анализ "побега" в кучу для всего проекта (исключая тесты)
# escape:
# 	@echo "Analyzing escape analysis for all modules..."
# 	go build -gcflags="-m" ./... 2>&1 | grep -v "_test.go" | grep -E "escapes to heap|moved to heap"
# 
# 
# ## lint: Проверка качества кода (требует golangci-lint)
# lint:
# 	@echo "Running linter..."
# 	./bin/golangci-lint run
# 
# ## clean: Удаление временных файлов и бинарников
# clean:
# 	@echo "Cleaning up..."
# 	rm -f $(BINARY_NAME)
# 	rm -f $(COVER_FILE)
# 	rm -f coverage.html
# 	rm -f ./storage.json
# 	@echo "Resetting test cache..."
# 	go clean -testcache
# 
# ## doc: Запуск локального сервера документации (godoc)
# doc:
# 	@echo "Starting documentation server at http://localhost:6060"
# 	@echo "Run 'go install golang.org/x/tools/cmd/godoc@latest' if not found"
# 	godoc -http=:6060
# 
# ## Help: Список доступных команд
# help:
# 	@echo "Usage:"
# 	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
