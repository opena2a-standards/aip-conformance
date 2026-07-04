#!/usr/bin/env python3
"""Validate every fixture's challenge/response transcript against the vendored spec schemas.

The schemas are the machine-readable models published by agent-identity-protocol
(schemas/{challenge-body,response-body}-v1.schema.json), vendored under
schemas/vendor/agent-identity-protocol/ and byte-drift-gated in CI against the
pinned AIP_SPEC_REF.

Contract: every fixture's challengeResponse.challenge validates against the
challenge-body schema and challengeResponse.response against the response-body
schema. All current REJECT fixtures are crypto/state rejects (replay, stale
challenge, wrong key), so they are shape-valid by design; a schema failure
means fixtures and schemas have drifted apart.
"""

import json
import pathlib
import sys

try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("error: the 'jsonschema' package is required (pip install jsonschema)")
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "schemas" / "vendor" / "agent-identity-protocol"


def load(name: str) -> Draft202012Validator:
    schema = json.loads((VENDOR / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def main() -> int:
    v_challenge = load("challenge-body-v1.schema.json")
    v_response = load("response-body-v1.schema.json")

    failures = 0
    fixtures = sorted((ROOT / "fixtures").glob("*.json"))
    if not fixtures:
        print("error: no fixtures found")
        return 1

    for path in fixtures:
        doc = json.loads(path.read_text(encoding="utf-8"))
        transcript = doc.get("challengeResponse")
        if not transcript or "challenge" not in transcript or "response" not in transcript:
            print(f"FAIL  {path.name}: missing challengeResponse.challenge/.response")
            failures += 1
            continue
        errs = [
            ("challenge", e) for e in v_challenge.iter_errors(transcript["challenge"])
        ] + [
            ("response", e) for e in v_response.iter_errors(transcript["response"])
        ]
        if errs:
            print(f"FAIL  {path.name}:")
            for part, err in errs:
                print(f"      {part} {err.json_path}: {err.message}")
            failures += 1
        else:
            print(f"PASS  {path.name}")

    print(f"\nsummary: {len(fixtures) - failures} pass, {failures} fail ({len(fixtures)} fixtures)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
