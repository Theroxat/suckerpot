from suckerpot_db.entrypoint import check_secrets

A, B, C = "a" * 24, "b" * 24, "c" * 24
GOOD = {"POSTGRES_PASSWORD": A, "POSTGRES_INGEST_PASSWORD": B, "POSTGRES_API_PASSWORD": C}


def test_good() -> None:
    assert check_secrets(GOOD) == []


def test_short() -> None:
    problems = check_secrets({**GOOD, "POSTGRES_API_PASSWORD": "short"})
    assert problems == ["POSTGRES_API_PASSWORD must be at least 24 characters"]


def test_duplicates() -> None:
    problems = check_secrets({**GOOD, "POSTGRES_API_PASSWORD": A})
    assert problems == ["POSTGRES_PASSWORD and POSTGRES_API_PASSWORD must be different"]


def test_missing_always_fails() -> None:
    env = {**GOOD, "SUCKERPOT_ALLOW_DEFAULT_SECRETS": "1"}
    del env["POSTGRES_INGEST_PASSWORD"]
    assert check_secrets(env) == ["POSTGRES_INGEST_PASSWORD is not set"]


def test_escape_hatch() -> None:
    env = {
        "POSTGRES_PASSWORD": "x",
        "POSTGRES_INGEST_PASSWORD": "x",
        "POSTGRES_API_PASSWORD": "x",
        "SUCKERPOT_ALLOW_DEFAULT_SECRETS": "1",
    }
    assert check_secrets(env) == []


def test_values_never_in_messages() -> None:
    secret = "supersecretvalue"  # noqa: S105
    assert all(secret not in p for p in check_secrets({**GOOD, "POSTGRES_API_PASSWORD": secret}))


def test_collector_and_analyzer_passwords_are_optional() -> None:
    assert check_secrets(GOOD) == []


def test_collector_and_analyzer_follow_the_policy_when_set() -> None:
    env = {**GOOD, "POSTGRES_COLLECTOR_PASSWORD": "short", "POSTGRES_ANALYZER_PASSWORD": B}
    assert check_secrets(env) == [
        "POSTGRES_COLLECTOR_PASSWORD must be at least 24 characters",
        "POSTGRES_INGEST_PASSWORD and POSTGRES_ANALYZER_PASSWORD must be different",
    ]


def test_collector_and_analyzer_distinct_from_each_other() -> None:
    d = "d" * 24
    ok = {**GOOD, "POSTGRES_COLLECTOR_PASSWORD": d, "POSTGRES_ANALYZER_PASSWORD": "e" * 24}
    assert check_secrets(ok) == []
    same = {**ok, "POSTGRES_ANALYZER_PASSWORD": d}
    assert check_secrets(same) == [
        "POSTGRES_COLLECTOR_PASSWORD and POSTGRES_ANALYZER_PASSWORD must be different"
    ]
