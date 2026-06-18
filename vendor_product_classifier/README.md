# Vendor/Product Classifier

Standalone background workers for classifying vulnerability MongoDB documents by vendor and product. The pipeline is independent of the Flask web server: it does not import `app.py`, routes, templates, sessions, Company AI, report generation, or any web UI code.

The only shared systems are MongoDB, RabbitMQ, `.env` secrets, and `config/classifier.json`.

## Pipeline

```text
scanner -> vendor_product_classification_intake -> classifier worker
                                               -> vendor_product_zero_shot -> zero-shot worker
                                               -> vendor_product_classification_dead
```

The scanner finds vulnerability documents without `classification.vendor` or `classification.product`, skips active/classified work, publishes a lightweight RabbitMQ task, and marks the document `queued`.

The classifier worker reloads the MongoDB document, applies rule/alias matching first, and writes a `classified` result when it finds an exact alias match. Unmatched documents are marked `pending_zero_shot` and sent to the zero-shot queue.

The zero-shot worker uses `sentence-transformers` with `BAAI/bge-small-en-v1.5` by default. It embeds document evidence and aliases from `aliases.json`, classifies matches above the configured threshold, and marks lower-confidence records `unclassified`.

## Configuration

Create `.env` from the example:

```bash
cp .env.example .env
```

Required secrets:

```env
ATLAS_MONGO_URI=
RABBITMQ_URL=
```

Non-secret settings live in `config/classifier.json`, including MongoDB database/collections, queue names, scanner interval, retry limits, and zero-shot model settings.

Logs are JSON lines written to stdout. The default level is `INFO`; set `CLASSIFIER_LOG_LEVEL=DEBUG` in the process environment for per-document scanner decisions, RabbitMQ publish details, and zero-shot embedding steps. Keep `.env` for secrets only.

Default queues:

- `vendor_product_classification_intake`
- `vendor_product_zero_shot`
- `vendor_product_classification_dead`

## MongoDB Fields

Queued documents are written as:

```json
{
  "classification": {
    "status": "queued",
    "queued_at": "ISO_DATE",
    "classifier_version": 1,
    "taxonomy_version": "ALIASES_SHA256_PREFIX"
  }
}
```

Successful rule matches use `method` values `rule_alias_strong` or `rule_alias_weak`. Successful zero-shot matches use `zero_shot_embedding`. Failures use `status: "failed"` with `error`, `attempts`, and `updated_at`.

Only the `classification` subdocument is updated.

Unclassified documents store the current `taxonomy_version`. The scanner skips unclassified records already checked against the current `aliases.json`, and automatically requeues them after the alias taxonomy changes.

## Docker

```bash
cd vendor_product_classifier
cp .env.example .env
# edit ATLAS_MONGO_URI and RABBITMQ_URL
docker compose up -d --build
```

Zero-shot is enabled by default. On the first zero-shot classification task, `zero-shot-worker` may download the embedding model into `./models`.

To debug with verbose logs:

```bash
CLASSIFIER_LOG_LEVEL=DEBUG docker compose up --build
```

## Native Python

```bash
cd vendor_product_classifier
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# edit .env
python classifier_scanner.py
python classifier_worker.py
python zero_shot_worker.py
```

Run each command in its own terminal or process supervisor.

## Test With One Document

Insert or update one test document in a configured collection:

```javascript
db.cisco.updateOne(
  { _id: "cisco:test-vmanage" },
  {
    $set: {
      title: "Example Cisco advisory",
      details: {
        cisco: {
          product_names: ["Cisco Catalyst SD-WAN Manager"]
        }
      },
      classification: { status: "unclassified" }
    }
  },
  { upsert: true }
)
```

After the scanner and worker run, the document should contain:

```json
{
  "classification": {
    "vendor": "Cisco",
    "product": "Catalyst SD-WAN Manager",
    "method": "rule_alias_strong",
    "status": "classified"
  }
}
```

## Local Tests

From the `avd` repository root:

```bash
pytest tests/test_vendor_product_classifier.py
```
