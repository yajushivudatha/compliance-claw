import pytest
import main  # triggers module-level code

@pytest.fixture(autouse=True)
def init_db():
    """Ensure the DB table exists before every test."""
    main.init_db()