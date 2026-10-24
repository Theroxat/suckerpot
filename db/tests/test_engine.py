from suckerpot_db.engine import database_url_from_env


def test_url_escapes_password() -> None:
    url = database_url_from_env(
        {
            "POSTGRES_USER": "u",
            "POSTGRES_PASSWORD": "p@ss/w:rd#?",
            "POSTGRES_HOST": "db",
            "POSTGRES_PORT": "5433",
            "POSTGRES_DB": "d",
        }
    )
    assert url == "postgresql+asyncpg://u:p%40ss%2Fw%3Ard%23%3F@db:5433/d"


def test_url_defaults() -> None:
    assert database_url_from_env({}) == "postgresql+asyncpg://suckerpot:@db:5432/suckerpot"
