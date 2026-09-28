#!/usr/bin/env python3

import copy
import json
import sys

import jsonschema


SCHEMA_PATH = "schemas/finding-schema.json"
EXAMPLE_PATH = "schemas/finding-example.json"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


schema = load_json(SCHEMA_PATH)
example = load_json(EXAMPLE_PATH)

passed = 0
failed = 0


def pass_test(name):
    global passed
    passed += 1
    print(f"[PASS] {name}")


def fail_test(name, message):
    global failed
    failed += 1
    print(f"[FAIL] {name}: {message}")


# Test 1: Valid assessment must be accepted.
try:
    jsonschema.validate(instance=example, schema=schema)
    pass_test("Valid findings accepted")
except Exception as exc:
    fail_test("Valid findings accepted", str(exc))


# Test 2: Port must be an integer.
data = copy.deepcopy(example)
data["findings"][2]["evidence"]["port"] = "hello"

try:
    jsonschema.validate(instance=data, schema=schema)
    fail_test("String port rejected", "invalid port was accepted")
except jsonschema.ValidationError:
    pass_test("String port rejected")


# Test 3: Port must be in the valid range.
data = copy.deepcopy(example)
data["findings"][2]["evidence"]["port"] = 70000

try:
    jsonschema.validate(instance=data, schema=schema)
    fail_test("Out-of-range port rejected", "port 70000 was accepted")
except jsonschema.ValidationError:
    pass_test("Out-of-range port rejected")


# Test 4: Required configuration evidence must exist.
data = copy.deepcopy(example)
del data["findings"][0]["evidence"]["observed_value"]

try:
    jsonschema.validate(instance=data, schema=schema)
    fail_test(
        "Missing evidence rejected",
        "missing observed_value was accepted"
    )
except jsonschema.ValidationError:
    pass_test("Missing evidence rejected")


print()
print(f"Tests passed: {passed}")
print(f"Tests failed: {failed}")

if failed:
    sys.exit(1)

print("ALL SCHEMA TESTS PASSED")
sys.exit(0)
