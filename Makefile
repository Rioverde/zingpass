.PHONY: run log restart stop clean psql

run:
	docker compose up --build -d

log:
	docker compose logs -f zingpass

restart:
	docker compose restart zingpass

stop:
	docker compose down

clean:
	docker compose down -v

psql:
	docker compose exec storage psql -U zingpass -d zingpass
