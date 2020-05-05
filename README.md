# Capsule API

Before any command, don't forget to activate your Python virtual environment
with something like that:

```sh
. venv/bin/activate
```

## Local Environment

```sh
$ cp .env.local .env

# To up the MySQL server.
$ docker-compose up -d

# If you want to remote the MySQL server and all its data:
$ docker-compose down -v

# To open a mysql client in the docker.
$ docker-compose exec db mysql -u root -p'password' capsule_local
```

## Database migration

```sh
$ export FLASK_APP=server.py

# To add a new migration :
$ python -m flask db migrate -m "My new migration"

# To apply a migration.
$ python -m flask db upgrade
```

## Run unit tests

```sh
pytest
```
