# Build services
build:
	docker-compose build

build-no-cache:
	docker-compose build --no-cache

# Start services in the foreground
up:
	docker-compose up

# Start services in the background
up-detached:
	docker-compose up -d

# Stop services
stop:
	docker-compose stop

# Stop and remove containers, networks, volumes, and images created by 'up'
down:
	docker-compose down

# View logs
logs:
	docker-compose logs

# Prune system - removes stopped containers, unused networks, dangling images, and build cache
prune:
	docker system prune -f

# Prune system including unused containers and images
prune-all:
	docker system prune -a -f

# Prune volumes - removes unused volumes
prune-volumes:
	docker volume prune -f

# Execute a command in a running container
# Usage: make exec service=[service_name] cmd="[command]"
exec:
	docker-compose exec $(service) $(cmd)

access:
	docker-compose exec nmap-container bash

clear_volumes:
	@echo "Removing all Docker volumes..."
	docker volume rm $(shell docker volume ls -q | ft_transcendence_ )
	@echo "All volumes have been removed."

start:
	docker-compose up --build

.PHONY: build up up-detached down stop logs prune prune-all prune-volumes exec clear_volumes start