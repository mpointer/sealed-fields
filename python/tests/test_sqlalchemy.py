"""SQLAlchemy column types: sealed at rest, plaintext in the ORM."""
import base64
import json

import pytest
import sqlalchemy as sa
from sqlalchemy import Column, Integer, MetaData, Table, Text, bindparam, insert, select, text
from sqlalchemy.orm import Session, declarative_base

from sealed_fields import (
    KeyNotConfiguredError,
    SealedFields,
    SealedFieldsError,
    UnknownKeyVersionError,
    create_sealed_fields,
    generate_key,
    is_sealed,
)
from sealed_fields.sqlalchemy import SealedJSON, SealedString, SealedText

KEY_A = generate_key()
KEY_B = generate_key()

SF_A = create_sealed_fields(namespaces={"PII": {"key": KEY_A}})
SF_B = create_sealed_fields(namespaces={"PII": {"key": KEY_B}})


class Current:
    """Stand-in for an app's lazily loaded keyring: tests swap `.sf`."""

    sf = SF_A


def current_sf():
    return Current.sf


Base = declarative_base()


class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True)
    body = Column(SealedText(SF_A))
    author = Column(SealedString(SF_A))
    snapshot = Column(SealedJSON(SF_A))
    lazy = Column(SealedText(current_sf))


@pytest.fixture
def engine():
    eng = sa.create_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


@pytest.fixture(autouse=True)
def reset_current():
    Current.sf = SF_A
    yield
    Current.sf = SF_A


def raw(session, column, note_id):
    return session.execute(
        text(f"SELECT {column} FROM notes WHERE id = :id"), {"id": note_id}
    ).scalar()


class TestSealedText:
    def test_stored_sealed_read_plain(self, session):
        secret = "slept nine hours, anxiety way down"
        n = Note(body=secret, author="Ada")
        session.add(n)
        session.commit()
        stored = raw(session, "body", n.id)
        assert is_sealed(stored)
        assert secret not in stored
        assert is_sealed(raw(session, "author", n.id))
        session.expire(n)
        assert n.body == secret
        assert n.author == "Ada"

    def test_none_stays_null_and_empty_string_is_sealed(self, session):
        n = Note(body=None, author="")
        session.add(n)
        session.commit()
        assert raw(session, "body", n.id) is None
        stored_author = raw(session, "author", n.id)
        assert is_sealed(stored_author)  # "" and NULL stay distinct
        session.expire(n)
        assert n.body is None
        assert n.author == ""

    def test_legacy_plaintext_row_reads_through(self, session):
        session.execute(
            text("INSERT INTO notes (body) VALUES (:b)"), {"b": "written before sealing"}
        )
        session.commit()
        n = session.execute(select(Note)).scalar_one()
        assert n.body == "written before sealing"

    def test_non_string_write_raises(self, session):
        session.add(Note(body=123))
        with pytest.raises(sa.exc.StatementError) as excinfo:
            session.commit()
        assert isinstance(excinfo.value.orig, TypeError)

    def test_tampered_token_raises_on_read(self, session):
        n = Note(body="secret")
        session.add(n)
        session.commit()
        stored = raw(session, "body", n.id)
        version, blob = stored.split(":", 1)
        bad = bytearray(base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4)))
        bad[-1] ^= 0x01
        forged = f"{version}:{base64.urlsafe_b64encode(bytes(bad)).decode().rstrip('=')}"
        session.execute(text("UPDATE notes SET body = :b WHERE id = :id"), {"b": forged, "id": n.id})
        session.commit()
        session.expire(n)
        with pytest.raises(Exception):
            n.body

    def test_lazy_provider_resolves_on_every_call(self, session):
        n = Note(lazy="under key A")
        session.add(n)
        session.commit()
        stored = raw(session, "lazy", n.id)
        assert SF_A.unseal(stored) == "under key A"

        Current.sf = SF_B  # rotate: the column must follow, no re-declaration
        m = Note(lazy="under key B")
        session.add(m)
        session.commit()
        assert SF_B.unseal(raw(session, "lazy", m.id)) == "under key B"
        session.expire(n)
        with pytest.raises(Exception):  # key A rows are unreadable under B alone
            n.lazy

    def test_unknown_version_raises_unless_passthrough(self, session):
        future = create_sealed_fields(namespaces={"PII": {"key": KEY_A, "version": "v7"}})
        n = Note(lazy="x")
        session.add(n)
        session.commit()
        token = future.seal("from the future")
        session.execute(text("UPDATE notes SET lazy = :t WHERE id = :id"), {"t": token, "id": n.id})
        session.commit()
        session.expire(n)
        with pytest.raises(UnknownKeyVersionError):
            n.lazy
        Current.sf = create_sealed_fields(
            namespaces={"PII": {"key": KEY_A}}, on_unknown_version="passthrough"
        )
        session.expire(n)
        assert n.lazy == token  # migration window: the token comes back as-is


class TestModes:
    def test_strict_without_key_refuses_to_write(self, session):
        Current.sf = create_sealed_fields(namespaces={"PII": {}})
        session.add(Note(lazy="pii"))
        with pytest.raises(sa.exc.StatementError) as excinfo:
            session.commit()
        assert isinstance(excinfo.value.orig, KeyNotConfiguredError)

    def test_dormant_without_key_writes_plaintext_and_warns_once(self, session):
        warnings = []
        Current.sf = create_sealed_fields(
            namespaces={"PII": {}}, mode="dormant", logger=warnings.append
        )
        n = Note(lazy="not yet keyed")
        m = Note(lazy="still not keyed")
        session.add_all([n, m])
        session.commit()
        assert raw(session, "lazy", n.id) == "not yet keyed"
        assert len(warnings) == 1 and "PLAINTEXT" in warnings[0]
        session.expire(n)
        assert n.lazy == "not yet keyed"

    def test_strict_without_key_cannot_read_a_token(self, session):
        n = Note(lazy="sealed under A")
        session.add(n)
        session.commit()
        Current.sf = create_sealed_fields(namespaces={"PII": {}})
        session.expire(n)
        with pytest.raises(KeyNotConfiguredError):
            n.lazy


class TestSealedJSON:
    def test_round_trips_list_and_dict(self, session):
        conditions = ["anxiety", "chronic pain", {"nested": [1, 2.5, None, "ü"]}]
        n = Note(snapshot=conditions)
        session.add(n)
        session.commit()
        stored = raw(session, "snapshot", n.id)
        assert is_sealed(stored)
        assert "anxiety" not in stored
        assert json.loads(SF_A.unseal(stored)) == conditions
        session.expire(n)
        assert n.snapshot == conditions

    def test_empty_list_and_none(self, session):
        n = Note(snapshot=[])
        m = Note(snapshot=None)
        session.add_all([n, m])
        session.commit()
        assert raw(session, "snapshot", m.id) is None
        session.expire(n)
        session.expire(m)
        assert n.snapshot == []
        assert m.snapshot is None

    def test_legacy_json_text_row_decodes(self, session):
        session.execute(
            text("INSERT INTO notes (snapshot) VALUES (:s)"), {"s": '["couch-lock","paranoia"]'}
        )
        session.commit()
        n = session.execute(select(Note)).scalar_one()
        assert n.snapshot == ["couch-lock", "paranoia"]

    def test_already_parsed_value_passes_through(self):
        # A column still typed json/jsonb hands the ORM a parsed value.
        t = SealedJSON(SF_A)
        assert t.process_result_value(["a", "b"], None) == ["a", "b"]
        assert t.process_result_value({"k": 1}, None) == {"k": 1}
        assert t.process_result_value(None, None) is None
        assert t.process_result_value("", None) is None
        assert t.process_result_value("not json", None) == "not json"

    def test_string_value_survives_as_string(self):
        t = SealedJSON(SF_A)
        stored = t.process_bind_param("free text", None)
        assert t.process_result_value(stored, None) == "free text"


class TestProviderAndCaching:
    def test_requires_a_provider(self):
        with pytest.raises(TypeError):
            SealedText()
        with pytest.raises(TypeError):
            SealedText(provider=42)

    def test_class_attribute_provider_allows_bare_use(self, engine):
        class EncryptedText(SealedText):
            cache_ok = True
            provider = staticmethod(current_sf)

        md = MetaData()
        t = Table("bare", md, Column("id", Integer, primary_key=True), Column("v", EncryptedText))
        md.create_all(engine)
        with engine.begin() as conn:
            conn.execute(t.insert().values(v="hello"))
            stored = conn.execute(text("SELECT v FROM bare")).scalar()
            assert is_sealed(stored)
            assert conn.execute(select(t.c.v)).scalar() == "hello"

    def test_provider_must_return_sealed_fields(self):
        t = SealedText(lambda: "nope")
        with pytest.raises(SealedFieldsError):
            t.process_bind_param("x", None)

    def test_namespace_is_honored(self):
        sf = create_sealed_fields(namespaces={"PII": {"key": KEY_A}, "TOTP": {"key": KEY_B}})
        t = SealedText(sf, namespace="TOTP")
        token = t.process_bind_param("secret", None)
        assert sf.unseal(token, "TOTP") == "secret"
        with pytest.raises(Exception):
            sf.unseal(token, "PII")
        assert t.process_result_value(token, None) == "secret"

    def test_cache_key_includes_provider_and_namespace(self):
        assert SealedText(SF_A)._static_cache_key == SealedText(SF_A)._static_cache_key
        assert SealedText(SF_A)._static_cache_key != SealedText(SF_B)._static_cache_key
        sf = create_sealed_fields(namespaces={"PII": {"key": KEY_A}, "TOTP": {"key": KEY_B}})
        assert (
            SealedText(sf, namespace="PII")._static_cache_key
            != SealedText(sf, namespace="TOTP")._static_cache_key
        )

    def test_compiled_cache_does_not_cross_providers(self, engine):
        # Bind processors are cached with the compiled statement. Two
        # statements with identical shape but different providers must each
        # seal under their own key.
        md = MetaData()
        t = Table("plain", md, Column("id", Integer, primary_key=True), Column("v", Text))
        md.create_all(engine)
        with engine.begin() as conn:
            conn.execute(
                insert(t).values(id=1, v=bindparam("v", type_=SealedText(SF_A))), {"v": "a"}
            )
            conn.execute(
                insert(t).values(id=2, v=bindparam("v", type_=SealedText(SF_B))), {"v": "b"}
            )
            rows = dict(conn.execute(text("SELECT id, v FROM plain")).all())
        assert SF_A.unseal(rows[1]) == "a"
        assert SF_B.unseal(rows[2]) == "b"

    def test_string_impl_kwargs_pass_through(self):
        t = SealedString(SF_A, length=512)
        assert t.impl.length == 512


class TestContext:
    def test_column_context_binds_and_rejects_a_moved_value(self, engine):
        md = MetaData()
        t = Table(
            "bound",
            md,
            Column("id", Integer, primary_key=True),
            Column("email", SealedText(SF_A, "PII", ["users", "email"])),
            Column("notes", SealedText(SF_A, "PII", "users.notes")),
        )
        md.create_all(engine)
        with engine.begin() as c:
            c.execute(insert(t).values(id=1, email="a@x", notes="hi"))
            assert c.execute(select(t.c.email)).scalar() == "a@x"
            stored = c.execute(text("SELECT email FROM bound")).scalar()
            assert SF_A.unseal(stored, context=["users", "email"]) == "a@x"
            c.execute(text("UPDATE bound SET notes = :v"), {"v": stored})
            with pytest.raises(Exception):
                c.execute(select(t.c.notes)).scalar()

    def test_context_is_part_of_the_cache_key(self):
        a = SealedText(SF_A, "PII", ["users", "email"])
        b = SealedText(SF_A, "PII", ["users", "notes"])
        assert a._static_cache_key != b._static_cache_key
