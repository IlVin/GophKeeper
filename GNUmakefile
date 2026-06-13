# Переменные проекта
WORKDIR=.

MAIN_SERVER=${WORKDIR}/cmd/server/main.go
BINARY_SERVER=${WORKDIR}/cmd/server/gophkeeper_server

MAIN_CLIENT=${WORKDIR}/cmd/client/main.go
BINARY_CLIENT=${WORKDIR}/cmd/client/gophkeeper_client


COVER_FILE=coverage.out
DOCKER_IMG=gophkeeper:latest

COMPOSE_FILE=infra/compose.yml

.PHONY: up down logs ps

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
