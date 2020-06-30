#!/bin/sh
# Docker Entrypoint

export GUNICORN_CMD_ARGS="--access-logfile - --error-logfile - --bind=0.0.0.0:5000 --workers=$WORKERS --preload"

exec gunicorn server:app "$@"