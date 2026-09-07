FROM python:3.13-slim

RUN useradd --create-home --uid 10001 finality
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .
USER 10001:10001
EXPOSE 8080 8081
ENTRYPOINT ["finality"]
