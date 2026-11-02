from suckerpot_db.shared_mail import SHARED_MAIL_DOMAINS, is_shared_domain


def test_free_mail_and_its_subdomains_are_shared() -> None:
    assert is_shared_domain("gmail.com") and is_shared_domain("IMAP.Gmail.com.")
    assert not is_shared_domain("example.net") and not is_shared_domain("")
    assert not is_shared_domain("notgmail.com") and not is_shared_domain(None)


def test_the_list_is_lower_case_without_dots() -> None:
    assert all(d == d.lower().strip(".") and "." in d for d in SHARED_MAIL_DOMAINS)
