#!/bin/bash

echo "Sourcing venv"
. ./venv/bin/activate

echo "Launch docker-compose"
docker-compose up -d

echo "Start keycloak"
echo start | ./keycloak/start.sh
