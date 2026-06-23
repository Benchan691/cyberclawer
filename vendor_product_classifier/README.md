# Vendor/Product Classifier

Standalone RabbitMQ workers that classify only the MongoDB `cve` collection.

## Pipeline

```text
scanner -> vendor_product_classification_intake -> classifier worker
                                               | dictionary lookup (hit -> MongoDB)
                                               -> vendor_product_zero_shot -> zero-shot worker
                                               -> vendor_product_classification_dead
```

The scanner queues CVE documents missing a final vendor/product classification. The classifier worker extracts vendor/product evidence from `details.cve.affected`, CPE in `details.cve.configurations`, root `title`, and English `details.cve.descriptions`, then searches the local CPE dictionary. On a hit it writes `method: dictionary` and skips zero-shot. On a miss it queues the zero-shot worker, which uses embeddings against the same dictionary.

## Configuration

```bash
cp .env.example .env
```

Required secrets:

```env
ATLAS_MONGO_URI=
RABBITMQ_URL=
```

`config/classifier.json` contains MongoDB, queue, retry, `dictionary_lookup`, model, and `cpe_dictionary.path` settings. `CPE_DICTIONARY_PATH` overrides the JSON path.

The bundled `fixtures/cpes.csv` is the default dictionary (`vendor`,`product` columns; full CPE URIs are synthesized). `fixtures/cpe_dictionary_sample.csv` remains available for small test fixtures.

## Classification Shape

See [`../database.md`](../database.md) for the canonical MongoDB schema. Successful records use classification v2:

```json
{
  "status": "classified",
  "vendor": "Cisco",
  "product": "IOS XE",
  "cpe": "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*",
  "confidence": 0.91,
  "method": "dictionary",
  "dictionary_version": "CPE_CSV_SHA256_PREFIX",
  "classifier_version": 2,
  "updated_at": "ISO_DATE"
}
```

## Docker

```bash
cd vendor_product_classifier
cp .env.example .env
docker compose up -d --build
```

To use a full dictionary:

```bash
CPE_DICTIONARY_PATH=/app/fixtures/cpes.csv docker compose up -d --build
```

## Dictionary upgrade migration

After switching dictionaries or fixing classification logic, re-run classification for all CVE records:

```bash
# from repo root — uses mongodb.toml for MongoDB and classifier.json for the CPE dictionary
vuln-scrape reclassify-cve --dry-run
vuln-scrape reclassify-cve --database vulnerabilities

# optional: embedding fallback for dictionary misses (slow on large collections)
vuln-scrape reclassify-cve --database vulnerabilities --zero-shot
```

Or from `vendor_product_classifier/` with `ATLAS_MONGO_URI` in `.env`:

```bash
python -m vendor_product_classifier.reclassify_cve --dry-run
python -m vendor_product_classifier.reclassify_cve --database vulnerabilities
```

The script scans every `cve` document, re-runs dictionary lookup (and optional zero-shot fallback), and overwrites `classification` when the result differs. Run `vuln-scrape migrate-mongo` first if legacy classification fields still need normalization.

## Native Python

```bash
cd vendor_product_classifier
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python classifier_scanner.py
python classifier_worker.py
python zero_shot_worker.py
```

## Tests

```bash
pytest tests/test_vendor_product_classifier.py
```
