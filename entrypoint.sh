#!/bin/sh
# Docker Entrypoint

# DO NOT USE --preload: this will fail with TLS.
# Without preload, each worker launch his own NATS listener, so that queueing is necessary.
#export GUNICORN_CMD_ARGS="--access-logfile - --error-logfile - --bind=0.0.0.0:5000 --workers=$WORKERS --preload"
export GUNICORN_CMD_ARGS="--access-logfile - --error-logfile - --bind=0.0.0.0:5000 --workers=$WORKERS"

if [ "${DB_MIGRATE}" = "upgrade" ] || [ "${DB_MIGRATE}" = "downgrade" ]; then
    FLASK_APP=server.py python -m flask db "${DB_MIGRATE}"
fi

exec gunicorn server:app "$@"