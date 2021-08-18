all: build down up

build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

piplock:
	docker-compose run --rm --no-deps --volume=${PWD}/src:/app/src --workdir=/app/src app pipenv install
	sudo chown -R ${USER} src/Pipfile.lock


