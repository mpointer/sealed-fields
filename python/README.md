# sealed-fields (Python)

Field-level encryption for PII at rest. This is the Python twin of the
[sealed-fields npm package](https://www.npmjs.com/package/sealed-fields):
identical wire format, identical API shape, shared cross-language test
vectors. Data sealed by either implementation unseals in the other.

```
pip install sealed-fields
```

```python
from sealed_fields import create_sealed_fields, generate_key

sf = create_sealed_fields(
    namespaces={"PII": {"key": os.environ["SEALED_KEY_PII"]}},
    blind_index_key=os.environ.get("SEALED_BLIND_INDEX_KEY"),
)

token = sf.seal("free-text note about a real person")  # "v1:..."
sf.unseal(token)                                        # plaintext
sf.blind_index("alice@example.com")                     # HMAC lookup token
```

See the [repository README](https://github.com/mpointer/sealed-fields) for
the full design: key rotation without a flag day, key namespaces, blind
index entropy rules, row helpers, legacy-format decoders, and the
fail-closed default.
