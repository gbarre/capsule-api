#!/bin/sh
# Docker Entrypoint

# DO NOT USE --preload: this will fail with TLS.
# Without preload, each worker launch his own NATS listener, so that queueing is necessary.
#export GUNICORN_CMD_ARGS="--access-logfile - --error-logfile - --bind=0.0.0.0:5000 --workers=$WORKERS --preload"
export GUNICORN_CMD_ARGS="--error-logfile - --workers=$WORKERS --timeout=$TIMEOUT"

if [ "${DB_MIGRATE}" = "upgrade" ] || [ "${DB_MIGRATE}" = "downgrade" ]; then
    FLASK_APP=server.py python -m flask db "${DB_MIGRATE}"
fi

if [ "${SSL}" = "true" ]; then
    export GUNICORN_CMD_ARGS="${GUNICORN_CMD_ARGS} --bind=0.0.0.0:5443 --certfile=${PWD}/cert/capsule.crt --keyfile=${PWD}/cert/capsule.key"
else
    export GUNICORN_CMD_ARGS="${GUNICORN_CMD_ARGS} --bind=0.0.0.0:5080"
fi

sed -i "s/__PLATFORM__/${PLATFORM}/g" spec/openapi.json
sed -i "s/__PLATFORM_DESCRIPTION__/${PLATFORM_DESCRIPTION}/g" spec/openapi.json

exec gunicorn server:app

