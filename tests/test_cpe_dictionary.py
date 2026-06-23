from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vendor_product_classifier.cpe_dictionary import (
    CpeDictionaryLookup,
    load_cpe_dictionary,
)


SAMPLE_FIXTURE = "fixtures/cpe_dictionary_sample.csv"
CPES_FIXTURE = "fixtures/cpes.csv"


def test_load_cpe_dictionary_from_vendor_product_csv() -> None:
    candidates = load_cpe_dictionary(CPES_FIXTURE)

    assert len(candidates) > 0
    first = candidates[0]
    assert first.vendor
    assert first.product
    assert first.cpe.startswith("cpe:2.3:a:")


def test_load_cpe_dictionary_from_full_nvd_style_csv() -> None:
    candidates = load_cpe_dictionary(SAMPLE_FIXTURE)

    assert len(candidates) == 3
    assert candidates[0].cpe == "cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*"
    assert candidates[0].vendor == "Cisco"
    assert candidates[0].product == "IOS XE"


def test_vendor_product_lookup_against_cpes_fixture() -> None:
    lookup = CpeDictionaryLookup(dictionary_path=CPES_FIXTURE)
    hit = lookup.lookup_cpe_strings(["cpe:2.3:a:cisco:ios_xe:*:*:*:*:*:*:*:*"])

    assert hit is not None
    assert hit.candidate.vendor == "cisco"
    assert hit.candidate.product == "ios xe"
