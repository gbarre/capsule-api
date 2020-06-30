#!/bin/sh
# Docker Entrypoint

export GUNICORN_CMD_ARGS="--access-logfile - --error-logfile - --bind=0.0.0.0:5000 --workers=$WORKERS --preload"

if [ "${DB_MIGRATE}" = "upgrade" ] || [ "${DB_MIGRATE}" = "downgrade" ]; then
    FLASK_APP=server.py python -m flask db "${DB_MIGRATE}"
fi

exec gunicorn server:app "$@"