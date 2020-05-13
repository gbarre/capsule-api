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

# To run the server.
$ python server.py
```

**Remark:** if the server is running, you can view the API specification
at the address http://localhost:5000/v1/ui/.


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


## How to create a local and complete dev environment

TODO...

Docker compose with a Keykloak and how install it...

Hack the code and create capsules and users...

```sh
curl --location --request POST 'http://localhost:5000/v1/capsules' \
    --header 'Content-Type: application/json' \
    --header "Authorization: Bearer $TOKEN" \
    --data-raw '{ "name": "Test-Capsule-1", "owners": [ "userfoo", "userbar" ] }'
```

## Get keycloak users

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

```
$ docker-compose exec db mysql -u root -p'XXXXX' capsule_local
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 16
Server version: 10.1.44-MariaDB-1~bionic mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [capsule_local]> select * from users;
+----------------------------------+----------+------+---------------------+---------------------+
| id                               | name     | role | created_at          | updated_at          |
+----------------------------------+----------+------+---------------------+---------------------+
| d889ead765e24d3581bfe10c98d53f41 | flafont2 | user | 2020-05-13 13:21:12 | 2020-05-13 13:21:12 |
| facb518592364fd7a2d7f07fe3cbb522 | gbarre2  | user | 2020-05-13 13:21:12 | 2020-05-13 13:21:12 |
+----------------------------------+----------+------+---------------------+---------------------+
2 rows in set (0.00 sec)

MariaDB [capsule_local]> update users set role = 'superadmin' where name = 'flafont2';
Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MariaDB [capsule_local]> update users set role = 'admin' where name = 'gbarre2';
Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MariaDB [capsule_local]> select * from users;
+----------------------------------+----------+------------+---------------------+---------------------+
| id                               | name     | role       | created_at          | updated_at          |
+----------------------------------+----------+------------+---------------------+---------------------+
| d889ead765e24d3581bfe10c98d53f41 | flafont2 | superadmin | 2020-05-13 13:21:12 | 2020-05-13 13:21:12 |
| facb518592364fd7a2d7f07fe3cbb522 | gbarre2  | admin      | 2020-05-13 13:21:12 | 2020-05-13 13:21:12 |
+----------------------------------+----------+------------+---------------------+---------------------+
2 rows in set (0.00 sec)

MariaDB [capsule_local]> quit;
Bye
```
