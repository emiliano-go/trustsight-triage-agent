"""Extract the verdict document from a model's final message.

The legacy FP-reproducer path asks the model for a verdict document as raw
JSON after its tool calls; this is the one tolerant reader for that text.
"""

from __future__ import annotations

import json


def extract_verdict(output: str) -> dict | None:
    """Last JSON object in the output that looks like a verdict.

    Decodes from every ``{`` position (nested objects break naive
    brace-matching regexes), so any embedded JSON is handled.
    """

    decoder = json.JSONDecoder()
    best = None
    for index, char in enumerate(output):
        if char != "{":
            continue
        try:
            doc, _ = decoder.raw_decode(output[index:])
        except ValueError:
            continue
        if (
            isinstance(doc, dict)
            and doc.get("schema_version") == 1
            and "verdict" in doc
            and "package" in doc
        ):
            best = doc
    return best
