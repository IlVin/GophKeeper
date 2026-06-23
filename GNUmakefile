# Переменные проекта
VERSION=v0.0.1
DATE=$(shell date +%Y-%m-%d)

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

# --- Переменные окружения для путей по умолчанию ---
# Разворачиваем переменные путей, куда Go-рантайм пишет оффлайн-контейнеры
HOME_DIR := $(shell echo $$HOME)
CLIENT_STATE_DIR := $(HOME_DIR)/.local/state/gophkeeper
CLIENT_CONFIG_DIR := $(HOME_DIR)/.config/gophkeeper

.PHONY: up down logs ps certs clean-certs



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

test-e2e:
	go test -tags=e2e ./internal/... -run E2E -count=1 -v

test-race:
	go test ./... -race -count=1

lint:
	golangci-lint run

build: build-linux

## build-linux: Сборка статических бинарников строго под Linux x86_64 для scratch-контейнера
build-linux: gen-proto
	@echo "Compiling static binaries for Linux containers..."
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X gophkeeper/internal/client/commands.Version=$(VERSION) -X gophkeeper/internal/client/commands.BuildDate=$(DATE)" -o $(BINARY_CLIENT) $(MAIN_CLIENT)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X gophkeeper/internal/client/commands.Version=$(VERSION) -X gophkeeper/internal/client/commands.BuildDate=$(DATE)" -o $(BINARY_SERVER) $(MAIN_SERVER)
	go build -ldflags  -o gophkeeper cmd/gophkeeper/main.go


## up: Сначала собирает Linux-бинарник на хосте, а затем мгновенно поднимает Docker-стек
up: certs build-linux
	@echo "Starting Docker containers..."
	docker compose -f $(COMPOSE_FILE) up -d --build

## down: Погасить сервис
down:
	docker compose -f $(COMPOSE_FILE) down

.PHONY: certs
certs:
	@mkdir -p internal/shared/certs/assets
	@mkdir -p .certs_private
	@echo "Generating System Root CAs (v4.1 Fixed PKI)..."
	
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
		
	@chmod 600 .certs_private/*.key
	@echo "--------------------------------------------------------"
	@echo "SUCCESS: Public certificates generated in internal/shared/certs/assets/"
	@echo "WARNING: Private keys saved OUTSIDE version control in .certs_private/"
	@echo "Pass these private key paths to your server via compose.yml or flags."



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

.PHONY: clean-vault
## clean-vault: Принудительное уничтожение локальных криптоконтейнеров SQLite и конфигураций
clean-vault:
	@echo "Stopping synchronization processes and wiping local cryptographic storage..."
	@# Удаляем все файлы баз данных (.db), WAL-журналы (-wal) и разделяемую память (-shm)
	@rm -rf $(CLIENT_STATE_DIR)/*.db $(CLIENT_STATE_DIR)/*.db-wal $(CLIENT_STATE_DIR)/*.db-shm
	@# Принудительно очищаем саму директорию состояния контейнеров
	@rm -rf $(CLIENT_STATE_DIR)
	@# Очищаем конфигурационный YAML-файл и его директорию
	@rm -rf $(CLIENT_CONFIG_DIR)
	@# Удаляем временные тестовые базы данных, если они создавались в корне репозитория
	@rm -f *.db *.db-wal *.db-shm
	@echo "✔ Success! All offline SQLite databases, WAL journals, and client configs have been securely deleted."

.PHONY: clean-all
## clean-all: Полная очистка репозитория (бинарники, protobuf, сертификаты и СУБД)
clean: down clean-vault proto-clean
	@echo "Purging compiled binaries..."
	@rm -rf ./cmd/gophkeeper/gophkeeper ./cmd/gophkeeper-server/gophkeeper-server
	@echo "✔ Entire local development state has been safely reset."

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
