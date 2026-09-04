"""Incident domain logic.

Rules about what an incident *is* and how it may change, with no database, no
session and no HTTP. Services and routers depend on this package; it depends on
neither.
"""
