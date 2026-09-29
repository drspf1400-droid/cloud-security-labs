import copy
import json
from pathlib import Path

import jsonschema
import pytest


SCHEMA_PATH = Path("schemas/finding-schema.json")
EXAMPLE_PATH = Path("schemas/finding-example.json")


def load_json(path):
    return json.loads(path.read_text())


@pytest.fixture
def schema():
    return load_json(SCHEMA_PATH)


@pytest.fixture
def example():
    return load_json(EXAMPLE_PATH)


def test_valid_findings_are_accepted(schema, example):
    jsonschema.validate(
        instance=example,
        schema=schema,
    )


def test_string_port_is_rejected(schema, example):
    data = copy.deepcopy(example)
    data["findings"][2]["evidence"]["port"] = "hello"

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            instance=data,
            schema=schema,
        )


def test_out_of_range_port_is_rejected(schema, example):
    data = copy.deepcopy(example)
    data["findings"][2]["evidence"]["port"] = 70000

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            instance=data,
            schema=schema,
        )


def test_missing_configuration_evidence_is_rejected(
    schema,
    example,
):
    data = copy.deepcopy(example)

    del data["findings"][0]["evidence"]["observed_value"]

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(
            instance=data,
            schema=schema,
        )
