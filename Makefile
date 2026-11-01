# Makefile

.PHONY: dev lint test docker-build

# Run the service locally (requires uvicorn and FastAPI installed)
# Adjust the module path if your app entry differs.
 dev:
	docker run --rm -it -p 8000:8000 nsfw-firewall:latest

# Lint the codebase using ruff and flake8
 lint:
	ruff .
	flake8 .

# Execute the test suite
 test:
	pytest

# Build the Docker image
 docker-build:
	docker build -t nsfw-firewall:latest .
