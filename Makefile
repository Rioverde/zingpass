COMPOSE      = docker compose
COMPOSE_ELK  = docker compose -f docker-compose.yaml -f docker-compose.elk.yaml

.PHONY: run all log log-elk restart stop clean psql ps swag

# Core stack only: storage, zingpass, zingweb
run:
	$(COMPOSE) up --build -d

# Everything: core + Elasticsearch + Kibana + Filebeat
all:
	$(COMPOSE_ELK) up --build -d

log:
	$(COMPOSE) logs -f zingpass

log-elk:
	$(COMPOSE_ELK) logs -f filebeat elasticsearch kibana

restart:
	$(COMPOSE) restart zingpass

# Stop EVERYTHING (works for both `run` and `all`)
stop:
	$(COMPOSE_ELK) down

# Stop everything and wipe volumes (DB, ES data)
clean:
	$(COMPOSE_ELK) down -v

psql:
	$(COMPOSE) exec storage psql -U zingpass -d zingpass

ps:
	$(COMPOSE_ELK) ps

# Regenerate Swagger docs from handler annotations.
swag:
	@command -v $$(go env GOPATH)/bin/swag >/dev/null || go install github.com/swaggo/swag/cmd/swag@latest
	$$(go env GOPATH)/bin/swag init -g cmd/zingpass/main.go -o docs --parseInternal
