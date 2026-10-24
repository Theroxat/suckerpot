import pytest
from argon2 import PasswordHasher

from api.hashpw import main


def test_prompt_flow_prints_only_the_hash(capsys: pytest.CaptureFixture[str]) -> None:
    answers = iter(["a long enough password", "a long enough password"])
    assert main([], prompt=lambda _: next(answers)) == 0
    out = capsys.readouterr().out.strip()
    assert out.startswith("$argon2id$") and "\n" not in out
    assert PasswordHasher().verify(out, "a long enough password")
    assert "a long enough password" not in out


def test_mismatch_and_short_password(capsys: pytest.CaptureFixture[str]) -> None:
    answers = iter(["a long enough password", "different password!!"])
    assert main([], prompt=lambda _: next(answers)) == 1
    assert capsys.readouterr().out == ""
    assert main([], prompt=lambda _: "short") == 1
    assert capsys.readouterr().out == ""


def test_stdin_mode(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--stdin"], stdin=lambda: "from stdin password\n") == 0
    assert PasswordHasher().verify(capsys.readouterr().out.strip(), "from stdin password")


def test_bad_usage() -> None:
    assert main(["--nope"]) == 2


def test_generated_hash_is_accepted_by_settings() -> None:
    import contextlib
    import io

    from api.auth import AuthSettings

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        main(["--stdin"], stdin=lambda: "from stdin password\n")
    s = AuthSettings.from_env(
        {"ADMIN_PASSWORD_HASH": buf.getvalue().strip(), "SESSION_SECRET": "z" * 32}
    )
    assert s.password_hash is not None
