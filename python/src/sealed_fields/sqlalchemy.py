"""SQLAlchemy column types that seal on write and unseal on read.

    pip install "sealed-fields[sqlalchemy]"

Three ``TypeDecorator`` subclasses: :class:`SealedText` (backed by ``Text``),
:class:`SealedString` (backed by ``String``) and :class:`SealedJSON` (a JSON
value serialized to text, then sealed, backed by ``Text``). Each takes a
*provider*: either a :class:`~sealed_fields.SealedFields` instance or a
zero-argument callable returning one, plus an optional namespace::

    from sealed_fields import sealed_fields_from_env
    from sealed_fields.sqlalchemy import SealedText, SealedJSON

    sf = sealed_fields_from_env(["PII"])

    class User(Base):
        __tablename__ = "users"
        id = Column(Integer, primary_key=True)
        email = Column(SealedText(sf))
        preferences = Column(SealedJSON(sf))

A callable provider is resolved on every write and read, so keys that are
loaded lazily (after models are declared, or re-read between tests) just
work. The callable should be cheap: return a cached instance.

Behavior at the boundaries, learned in production and kept deliberately:

* ``None`` is stored as SQL NULL and read back as ``None``. An empty string
  is sealed like any other value, so ``""`` and ``NULL`` stay distinct.
* A column may hold plaintext rows mid-migration: ``unseal`` passes any
  non-token string through unchanged, so swapping a column to these types
  is a safe deploy before the backfill runs.
* With no key configured, the SealedFields ``mode`` decides what a write
  does. ``"strict"`` (the default) raises, so a dropped environment variable
  cannot silently store PII in the clear. ``"dormant"`` writes plaintext and
  logs one loud warning per process; choose it only for the deploy window
  before keys are provisioned, and never in production.
* A tampered, truncated or wrong-key token raises on read. These types do
  not null the value the way the row helpers do, because a per-column type
  has no batch to measure a systemic failure against, and a silent ``None``
  in an ORM attribute is how ciphertext problems go unnoticed for months.
* Ciphertext is longer than plaintext (about 1.4x the UTF-8 byte length plus
  roughly 50 bytes of nonce, tag and version). Size the backing column for
  that, not for the plaintext.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Optional, Sequence, Union

from sqlalchemy.types import String, Text, TypeDecorator

from . import SealedFields, SealedFieldsError

__all__ = ["SealedText", "SealedString", "SealedJSON", "Provider"]

Provider = Union[SealedFields, Callable[[], SealedFields]]


class _SealedType(TypeDecorator):
    """Shared plumbing: provider resolution and the seal/unseal calls."""

    cache_ok = True

    #: A subclass may set this so the type can be used without arguments
    #: (``Column(MyText)``), the way a project-local alias usually is. Every
    #: TypeDecorator subclass must restate ``cache_ok``, or SQLAlchemy stops
    #: caching statements that use it and warns::
    #:
    #:     class EncryptedText(SealedText):
    #:         cache_ok = True
    #:         provider = staticmethod(get_sealed_fields)
    provider: Optional[Provider] = None

    def __init__(
        self,
        provider: Optional[Provider] = None,
        namespace: Optional[str] = None,
        context: Union[str, Sequence[str], None] = None,
        **impl_kwargs: Any,
    ) -> None:
        # `namespace` and `context` are positional-or-keyword on purpose: SQLAlchemy builds
        # the cache key from positional-or-keyword __init__ names only, and a
        # keyword-only one would be left out of it.
        super().__init__(**impl_kwargs)
        resolved = provider if provider is not None else type(self).provider
        if resolved is None:
            raise TypeError(
                f"{type(self).__name__} needs a provider: a SealedFields instance or a "
                "zero-argument callable returning one."
            )
        if not isinstance(resolved, SealedFields) and not callable(resolved):
            raise TypeError(
                f"{type(self).__name__} provider must be a SealedFields instance or a "
                f"callable, not {type(resolved).__name__}."
            )
        # Both attributes are part of the SQLAlchemy cache key (cache_ok=True
        # keys on the __init__ argument names found in __dict__). Bind and
        # result processors are cached with the compiled statement, so two
        # columns sealed by different providers must never share one.
        self.provider = resolved
        self.namespace = namespace
        # Column-level binding only (e.g. "users.ssn"): these hooks never see
        # the row. A tuple keeps the cache key hashable.
        self.context = context if context is None or isinstance(context, str) else tuple(context)

    def _sf(self) -> SealedFields:
        p = self.provider
        sf = p if isinstance(p, SealedFields) else p()  # type: ignore[operator]
        if not isinstance(sf, SealedFields):
            raise SealedFieldsError(
                f"{type(self).__name__} provider returned {type(sf).__name__}, "
                "expected a SealedFields instance."
            )
        return sf

    def _seal(self, value: str) -> str:
        return self._sf().seal(value, self.namespace, context=self.context)

    def _unseal(self, value: str) -> str:
        return self._sf().unseal(value, self.namespace, context=self.context)


class SealedText(_SealedType):
    """Text column sealed at rest.

    Writes seal the string with the namespace's active key. Reads unseal a
    token and pass plaintext (a row written before the backfill) through
    unchanged.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise TypeError(
                f"{type(self).__name__} expects str or None, got {type(value).__name__}."
            )
        return self._seal(value)

    def process_result_value(self, value: Any, dialect: Any) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            return value
        return self._unseal(value)


class SealedString(SealedText):
    """:class:`SealedText` backed by ``String`` instead of ``Text``, for call
    sites that previously declared ``String``. Pass ``length=`` sized for
    the ciphertext, not the plaintext, or leave it unset.
    """

    impl = String
    cache_ok = True


class SealedJSON(_SealedType):
    """JSON value (list or dict) sealed at rest.

    The value is serialized to compact JSON text, then sealed, so the backing
    column is ``Text``, not ``json`` or ``jsonb``. On read, a value the driver
    already parsed (a column still typed ``json``/``jsonb`` because the
    migration to text has not run yet) is returned as-is; only strings are
    unsealed and decoded.

    Like ``JSON``, SQLAlchemy persists a reassigned value (``obj.col = new``)
    but does not track an in-place mutation (``obj.col.append(x)``).
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: Any, dialect: Any) -> Optional[str]:
        if value is None:
            return None
        payload = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        return self._seal(payload)

    def process_result_value(self, value: Any, dialect: Any) -> Any:
        if value is None:
            return None
        if not isinstance(value, str):
            return value
        decoded = self._unseal(value)
        if decoded is None or decoded == "":
            return None
        try:
            return json.loads(decoded)
        except ValueError:
            return decoded  # legacy text that was never JSON; never lose it
