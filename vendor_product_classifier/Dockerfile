FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    SENTENCE_TRANSFORMERS_HOME=/app/models

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY __init__.py ./
COPY aliases.json ./
COPY classifier_scanner.py classifier_worker.py zero_shot_worker.py ./
COPY logging_utils.py mongo_utils.py rabbitmq_utils.py rule_alias.py ./
COPY README.md ./
COPY config/classifier.json config/classifier.json
RUN mkdir -p models

CMD ["python", "classifier_worker.py"]
