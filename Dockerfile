FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY sentinel_soc_defense /srv/sentinel_soc_defense
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin defender
USER 10001:10001
EXPOSE 8080
CMD ["python", "-m", "sentinel_soc_defense.adapter", "--host", "0.0.0.0", "--port", "8080"]
