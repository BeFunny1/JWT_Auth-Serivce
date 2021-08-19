all: build down up

build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

piplock:
	docker-compose run --rm --no-deps --volume=${PWD}/src:/src --workdir=/src auth_service pipenv install
	sudo chown -R ${USER} src/Pipfile.lock

psql:
	docker exec -it db psql -U postgres
