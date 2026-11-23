FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml /app/
COPY src /app/src
RUN pip install --no-cache-dir . \
    && useradd --uid 10001 --create-home connector \
    && mkdir /data && chown connector:connector /data
USER 10001:10001
VOLUME ["/data"]
ENTRYPOINT ["joe-falcon", "--config", "/app/config.toml"]
CMD ["run"]
