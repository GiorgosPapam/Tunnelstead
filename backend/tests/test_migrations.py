from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from vpnix_create import db as dbmod
from vpnix_create.db import Base


def test_migrations_match_models(app):
    with dbmod._engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert diff == [], f"models and migrations differ: {diff}"
