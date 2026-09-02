"""Shared schema helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, field_serializer
from pydantic.alias_generators import to_camel

T = TypeVar("T")


def as_utc(value: datetime | None) -> datetime | None:
    """Stamp a naive datetime as UTC.

    Everything in AEGISX is stored in UTC, but not every backend hands it back
    with an offset: PostgreSQL's ``timestamptz`` does, SQLite does not. A naive
    ISO string on the wire is read by the browser as *local* time, so the same
    event renders hours out depending on which database is behind the API.
    Timestamps are stamped here so the wire format is unambiguous regardless.
    """
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


class CamelModel(BaseModel):
    """Base model that serializes to camelCase for the TypeScript frontend."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
        # V3 introduced fields named `model`, `modelVersion` and `modelType`.
        # They describe an ML model, and Pydantic's default `model_` namespace
        # guard would rename or warn on them; the base class owns none of those
        # attribute names, so releasing the namespace is safe and keeps the wire
        # format saying what it means.
        protected_namespaces=(),
    )

    @field_serializer("*", when_used="always")
    def _serialize_datetimes(self, value: Any) -> Any:
        """Emit every datetime as an unambiguous UTC instant.

        Applied to every field rather than annotating each one: the rule is a
        property of the API contract, not of any particular schema, and a new
        timestamp field should not be able to reintroduce the ambiguity by
        being declared without the annotation.
        """
        if isinstance(value, datetime):
            return as_utc(value)
        return value


class Page(CamelModel, Generic[T]):
    """Envelope for paginated list endpoints."""

    items: list[T]
    total: int
    limit: int
    offset: int


class Message(CamelModel):
    detail: str
