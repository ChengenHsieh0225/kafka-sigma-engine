FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY sigma_rules/ sigma_rules/

ENV PYTHONPATH=/app
ENV SIGMA_RULES_DIR=/app/sigma_rules
ENV METRICS_PORT=8001

CMD ["python", "-m", "src.rule_engine.main"]
