FROM python:3.6-slim AS build

RUN apt-get update
RUN apt-get install -y --no-install-recommends build-essential gcc

WORKDIR /capsule-api

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY api api
COPY migrations migrations
COPY nats nats
COPY spec/openapi.json spec/openapi.json
COPY app.py .
COPY config.py .
COPY exceptions.py .
COPY models.py .
COPY server.py .
COPY utils.py .
COPY entrypoint.sh .

FROM python:3.6-slim AS run

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y; \
    rm -rf /var/lib/apt/lists/*; \
    apt-get clean

WORKDIR /capsule-api

COPY --from=build /opt/venv /opt/venv
COPY --from=build /capsule-api .

RUN groupadd -r capsule-api && useradd -r -g capsule-api capsule-api
RUN chown -R capsule-api:capsule-api /capsule-api
RUN chmod u+x entrypoint.sh

USER capsule-api:capsule-api

EXPOSE 5000

ENV PATH="/opt/venv/bin:$PATH"
ENV WORKERS="4"
# ENV DB_MIGRATE="upgrade" # or "downgrade"

ENTRYPOINT ["/capsule-api/entrypoint.sh"]