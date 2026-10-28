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

## SQLAlchemy column types

```
pip install "sealed-fields[sqlalchemy]"
```

Declare the sealing on the column and the ORM does the rest: sealed on
write, unsealed on read, plaintext rows from before the backfill read
through unchanged.

```python
from sqlalchemy import Column, Integer, String
from sealed_fields import sealed_fields_from_env
from sealed_fields.sqlalchemy import SealedJSON, SealedString, SealedText

sf = sealed_fields_from_env(["PII"])

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(SealedText(sf))
    email_idx = Column(String(64), index=True)   # sf.blind_index(email), set by the app
    display_name = Column(SealedString(sf))
    preferences = Column(SealedJSON(sf))         # list or dict, stored as sealed JSON text
```

Each type takes a provider, either a `SealedFields` instance or a
zero-argument callable returning one, and an optional `namespace`. A
callable is resolved on every read and write, so keys loaded after the
models are declared, or swapped between tests, are picked up without
redeclaring any column. Keep the callable cheap: return a cached instance.

```python
from functools import lru_cache
from sealed_fields import SealedFields, sealed_fields_from_env

@lru_cache(maxsize=1)
def current_sf() -> SealedFields:
    return sealed_fields_from_env(["PII"])   # tests call current_sf.cache_clear()

class Note(Base):
    body = Column(SealedText(current_sf, namespace="PII"))
```

What happens at the boundary, each one a production lesson:

- `None` is SQL `NULL` both ways. An empty string is sealed like any other
  value, so `""` and `NULL` stay distinct.
- A non-string value raises `TypeError` on write. Sealing needs text; a
  silent `str()` would hide a bug.
- With no key configured, the `SealedFields` mode decides. `"strict"` (the
  default) raises on write, so a dropped environment variable cannot store
  PII in the clear. `"dormant"` writes plaintext and logs one warning per
  process. Use dormant only for the deploy window before keys exist, and
  never in production:

  ```python
  mode = "strict" if os.environ.get("APP_ENV") == "production" else "dormant"
  ```

- A tampered, truncated or wrong-key token raises on read. These types do
  not null the value the way the row helpers do: a single column has no
  batch to measure a systemic failure against, and a quiet `None` in an
  ORM attribute is how a wrong key goes unnoticed for months.
- A token naming a key version that is not in the keyring raises
  `UnknownKeyVersionError`. During a rotation, build the `SealedFields`
  with `on_unknown_version="passthrough"` and the token comes back as-is.
- Plaintext in the column reads through unchanged by default. With
  `plaintext="reject"` on the `SealedFields`, it raises instead.
- `SealedJSON` serializes with compact separators and `ensure_ascii=False`
  before sealing, and parses after unsealing. The backing column is `Text`,
  not `json` or `jsonb`. If a column is still `json`/`jsonb` because that
  migration has not run yet, the driver hands back an already-parsed value
  and the type returns it untouched. Like `JSON`, SQLAlchemy persists a
  reassigned value but not an in-place mutation.
- Ciphertext is about 1.4x the UTF-8 byte length plus roughly 50 bytes.
  Size `SealedString(sf, length=...)` for that, or use `SealedText`.

A project-local alias so columns can say `Column(EncryptedText)` with no
arguments: subclass, set `provider`, and restate `cache_ok` (SQLAlchemy
requires every `TypeDecorator` subclass to declare it, or it stops caching
statements that use the type and warns).

```python
class EncryptedText(SealedText):
    cache_ok = True
    provider = staticmethod(current_sf)
```

The provider and namespace are part of the SQLAlchemy cache key. Bind and
result processors are cached with the compiled statement, so two columns
sealed by different keyrings never share one; the test suite proves it with
two identical statements and two providers.

Tested against SQLAlchemy 1.4 and 2.x on every push.
