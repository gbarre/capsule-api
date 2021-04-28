# Capsule-API Documentation

![python versions](https://img.shields.io/badge/Python-3.6%20%7C%203.7%20%7C%203.8-blue.svg)

| CI | Pipeline / build | Coverage |
|----|------------------|----------|
| Gitlab (internal) | [![pipeline status](https://git.in.ac-versailles.fr/capsule/capsapi/badges/master/pipeline.svg)](https://git.in.ac-versailles.fr/capsule/capsapi/commits/master) | [![coverage report](https://git.in.ac-versailles.fr/capsule/capsapi/badges/master/coverage.svg)](https://git.in.ac-versailles.fr/capsule/capsapi/commits/master) |
| Github (travis) | [![Build Status](https://travis-ci.com/gbarre/capsule-api.svg?branch=master)](https://travis-ci.com/gbarre/capsule-api) | N/A |

## Run the capsule API server in the development environment

**Requirements** : to run the full stack, you need to install:

- docker
- docker-compose
- python3.6 (or higher)
- python3.6-dev
- jq

Then:

```sh
# You have to activate a virtualenv and install the required packages.
python3 -m venv ./venv
. venv/bin/activate
pip install --upgrade pip
pip install --upgrade setuptools
pip install -r requirements.txt
pip install -r test-requirements.txt # If you want to be able to run tests too.

# Run a docker instance of keycloak a valid config file ./config-dev.yml
# for the capsule-api server will be created.
./keycloak/start.sh

# To up the local MySQL server and the NATS server.
docker-compose up -d

# To open a mysql client in the docker.
#
#docker-compose exec db mysql -u root -p'local' capsule_local

# To apply a migration of the database.
FLASK_APP=server.py CAPSULE_API_CONFIG=config-dev.yml python -m flask db upgrade

# And then, to run a dev/test capsule-api server (not relevant for a production server).
python -Wd server.py -c config-dev.yml
```

**Remark:** if the server is running, you can view the API specification
at the address [http://localhost:5000/v1/ui/](http://localhost:5000/v1/ui/).

## To stop capsule API server and remove all docker instances

Type `CTRL+c` to stop the current execution of capsule-api server.
Then, to remove all docker instances (keyloack, MySQL and NATS):

```sh
# Remove the keycloak instance.
docker stop keycloak_dev && docker rm keycloak_dev

# Remove the NATS and MySQL instances.
# Warning, -v option remove the MySQL volume and you will lose all data.
# Don't mention the -v option if you want to keep the MySQL volume.
docker-compose down -v
```

## Database migration

```sh
# To add a new migration :
FLASK_APP=server.py CAPSULE_API_CONFIG=config-dev.yml python -m flask db migrate -m "My new migration"

# To apply a migration.
FLASK_APP=server.py CAPSULE_API_CONFIG=config-dev.yml python -m flask db upgrade
```

## Run tests

```sh
# To run cover (which includes tests)
python -m pytest -v -n8 --cov=. --cov-config=.coveragerc-ci --cov-report html --cov-report term tests/api/

# To run lint
flake8 --extend-exclude=venv,migrations --ignore=E402

# To run secaudit
bandit -n5 -x "./venv/*,./tests/*,./dev-tools/*" -r . -ll
```

## Update API specifications

After updating the API spec, you must rebuild the `openapi.json` file with this command:

```sh
docker run --rm -v "$PWD/spec:/spec" -it jeanberu/swagger-cli swagger-cli bundle -o /spec/openapi.json /spec/index.yaml
```

## Run production server

```sh
gunicorn --access-logfile - --bind 0.0.0.0:5000 -w 4 --preload server:app
```

## Run the docker production server

```sh
docker run --rm \
  -v $PWD/config.yml:/etc/capsule-api/config.yml \
  --net=host \
  -e WORKERS=8 \
  -e DB_MIGRATE=upgrade \
  --name capsule-api \
  gbarre2/capsule-api
```

To use with HTTPS **in development** run:

```sh
docker run --rm \
  -v $PWD/config.yml:/etc/capsule-api/config.yml \
  --net=host \
  -e WORKERS=8 \
  -e DB_MIGRATE=upgrade \
  -e SSL=true \
  --name capsule-api \
  gbarre2/capsule-api
```

To use with HTTPS **with your certificate** run:

```sh
docker run --rm \
  -v $PWD/config.yml:/etc/capsule-api/config.yml \
  --net=host \
  -e WORKERS=8 \
  -e DB_MIGRATE=upgrade \
  -e SSL=true \
  -v ${PATH_TO_CRT_FILE}:/capsule-api/cert/capsule.crt \
  -v ${PATH_TO_KEY_FILE}:/capsule-api/cert/capsule.key \
  --name capsule-api \
  gbarre2/capsule-api
```

## A few usefull commands

### Hack the code and create capsules and users

```sh
curl --location --request POST 'http://localhost:5000/v1/capsules' \
    --header 'Content-Type: application/json' \
    --header "Authorization: Bearer $TOKEN" \
    --data-raw '{ "name": "Test-Capsule-1", "owners": [ "userfoo", "userbar" ] }'
```

### Get keycloak users

```sh
#!/bin/sh

# requires jq

# config
KEYCLOAK_URL=https://keycloak.example.com/auth
KEYCLOAK_REALM=my_realm
KEYCLOAK_CLIENT_ID=my_client_id
KEYCLOAK_CLIENT_SECRET=ffffffff-ffff-ffff-ffff-ffffffffffff

# DO NOT EDIT NEXT THIS LINE
FILTER=""
USER="$1"

# Get valid token
RESULT=`curl -s --data "grant_type=client_credentials&client_id=${KEYCLOAK_CLIENT_ID}&client_secret=${KEYCLOAK_CLIENT_SECRET}" \
  ${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`
export TKN=$(echo $RESULT | jq -r '.access_token')

# Look for specific user ?
if [ ! -z $USER ]
then
  FILTER="?username=${USER}"
fi

# Get user(s)
curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users/${FILTER}" \
-H "Accept: application/json" \
-H "Authorization: Bearer $TKN"

```

### Send Nats request to simulate a driver

**Warning**: ensure all private/public keys are setted in the `config.ylm`.

```sh
cd dev-tools
python publish_msg.py --nats=localhost:4222 --subject="capsule.addon.ecea7683-92a8-4e2d-a846-be3c92f01308" --state="?list" --data='{}'
python publish_msg.py --nats=localhost:4222 --subject="capsule.webapp" --state="?state" --data='{"id": "19129f93-b50c-4d06-9c96-d779d1dac467"}'
```

## TODO

- API:
  - manage capsule "size"
  - manage cluster "total size"
  - add webapp/addon status-flag
- Front:
  - capsule:
    - Send error message before the end of creation
    - Catch owner repetition on creation
    - Check if user exists in keycloak after the local search fails
  - webapp:
    - TLS certificate & key options must be editable separately
    - TLS certificate warning : "mettre le certif suivi, le cas échéant, des certificats intermédiaires"
    - Add message for multiples FQDNs : "Only one principal" => change alias/principal management
    - Manage Error messages
  - addons:
    - adding / removing addon redirect to another capsule (seems to reload all)
    - Change "file" option (like webapp)
    - Script to check consistency between sqlite & existing databases
  - sshkeys:
    - Show sshkey comment if exists
    - Permit multiple spaces in sshkey comment
- Drivers:
  - k8s:
    - Ensure changing env variable run `kubectl apply`
