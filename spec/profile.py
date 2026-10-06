"""Small RFC8785 serializer for this profile's integer-only JSON subset.

Not a general JCS implementation: non-integer numbers are intentionally rejected.
No Unicode normalization occurs. Property ordering uses UTF-16 code units.
"""

import base64
import hashlib
import json

PROFILE = "KF-JSON-0.2"
MAX = 9007199254740991


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def loads(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON property: " + key)
            result[key] = value
        return result

    def forbidden(value):
        raise ValueError("non-integer JSON number: " + value)

    value = json.loads(
        raw, object_pairs_hook=pairs, parse_float=forbidden, parse_constant=forbidden
    )
    jcs(value)  # Validate Unicode and numeric domain even outside signed payloads.
    return value


def jcs(value):
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        if abs(value) > MAX:
            raise ValueError("integer exceeds exact JSON safe range")
        return str(value).encode("ascii")
    if isinstance(value, str):
        value.encode("utf-8", errors="strict")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(value, list):
        return b"[" + b",".join(jcs(item) for item in value) + b"]"
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        keys = sorted(value, key=lambda key: key.encode("utf-16-be", errors="strict"))
        return b"{" + b",".join(jcs(key) + b":" + jcs(value[key]) for key in keys) + b"}"
    raise ValueError("profile accepts only safe-integer JSON values")


def domain(kind=None):
    suffix = "" if kind is None else "/" + kind
    return ("KedgeFlow/" + PROFILE + suffix).encode("ascii") + b"\0"


def hash_value(kind, value):
    return hashlib.sha256(domain(kind) + jcs(value)).hexdigest()


def proposal_digest(envelope):
    return hash_value("proposal", {"schema": envelope["schema"], "payload": envelope["payload"]})


def record_digest(envelope):
    return (
        proposal_digest(envelope)
        if envelope["kind"] == "proposal"
        else hash_value(envelope["kind"], envelope)
    )


def signing_bytes(envelope):
    return domain() + jcs({key: value for key, value in envelope.items() if key != "signature"})
