# Makefile
# ML-Chain Development Shortcuts

.PHONY: help dev up down logs clean test test-adversarial db-reset

help:
	@echo "ML-Chain Development Commands"
	@echo "=============================="
	@echo "make dev              - Start full development environment"
	@echo "make up               - Start services in background"
	@echo "make down             - Stop all services"
	@echo "make logs             - Tail all logs"
	@echo "make clean            - Remove all containers and volumes"
	@echo "make test             - Run standard tests"
	@echo "make test-adversarial - Run red team tests"
	@echo "make db-reset         - Reset database (DESTRUCTIVE)"

dev:
	docker compose up --build

up:
	docker compose up -d
	@echo "✓ Services started"
	@echo "→ Notary Server: http://localhost:3000"
	@echo "→ Grafana: http://localhost:3001 (admin/admin)"
	@echo "→ Prometheus: http://localhost:9090"

down:
	docker compose down

logs:
	docker compose logs -f

clean:
	docker compose down -v
	@echo "⚠ All data has been deleted!"

test:
	pytest tests/ -v --tb=short

test-adversarial:
	pytest tests/test_adversarial.py -v --html=reports/adversarial.html

db-reset:
	docker compose exec postgres psql -U mlchain -d mlchain -f /docker-entrypoint-initdb.d/init.sql
	@echo "✓ Database reset complete"
