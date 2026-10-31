import ipaddress

import pytest

from collector.validate import UrlRefused, normalize_url, resolve_redirect


def refused(url: str, **kw: object) -> str:
    with pytest.raises(UrlRefused) as exc:
        normalize_url(url, **kw)  # type: ignore[arg-type]
    return exc.value.code


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("file:///etc/passwd", "bad_scheme"),
        ("gopher://files.example.test/", "bad_scheme"),
        ("javascript:alert(1)", "bad_scheme"),
        ("ftp://files.example.test/x", "unsupported"),
        ("tftp://files.example.test/x", "unsupported"),
        ("http:///nohost", "no_host"),
        ("http://user:pw@files.example.test/", "userinfo"),
        ("http://files.example.test@127.0.0.1/", "userinfo"),
        ("http://files.example.test:0/", "bad_port"),
        ("http://files.example.test:65536/", "bad_port"),
        ("http://files.example.test:80a/", "bad_port"),
        ("http://files.example.test:/", "bad_port"),
        ("http://files.example.test\\@evil.test/", "bad_chars"),
        ("http://files.example.test/a b", "bad_chars"),
        ("http://files.example.test/\x00", "bad_chars"),
        # numeric spellings of an IPv4 address
        ("http://3232235777/", "ip_form"),  # decimal
        ("http://0xC0A80101/", "ip_form"),  # hex
        ("http://0300.0250.0.1/", "ip_form"),  # octal
        ("http://172.16.1/", "ip_form"),  # short form
        ("http://127.1/", "ip_form"),
        ("http://1.2.3.4.5/", "ip_form"),
        ("http://010.1.1.1/", "ip_form"),  # leading zero
        ("http://[fe80::1%25eth0]/", "ip_form"),  # zone id
        # single-label and special names
        ("http://localhost/", "single_label"),
        ("http://redis/", "single_label"),
        ("http://db:5432/", "single_label"),
        ("http://files/x", "single_label"),
        ("http://localhost.localdomain/", "denied_host"),
        ("http://printer.local/", "denied_host"),
        ("http://a.localhost/", "denied_host"),
        ("http://nas.internal/", "denied_host"),
        ("http://router.lan/", "denied_host"),
        ("http://x.home.arpa/", "denied_host"),
        ("http://4.3.2.1.in-addr.arpa/", "denied_host"),
        ("http://-bad..example.test/", "bad_host"),
        ("http://x.suckerpot_egress-proxy/", "bad_host"),
        ("http://vpn.suckerpot_samples/", "bad_host"),
        ("http://vpn.suckerpot_egress-proxy:8000/v1/publicip/ip", "bad_host"),
        ("http://vpn.suckerpotbackend/", "denied_host"),
        ("http://files.vpn/", "denied_host"),
        ("http://x.db/", "denied_host"),
        ("http://x.redis/", "denied_host"),
        ("http://a.b.123/", "ip_form"),
        ("http://a.b.c1/", "denied_host"),
        # address blocks
        ("http://127.0.0.1/", "ip_forbidden"),
        ("http://10.0.0.1/", "ip_forbidden"),  # gitleaks:allow (private range must be refused)
        ("http://172.16.5.4/", "ip_forbidden"),  # gitleaks:allow (private range must be refused)
        ("http://172.16.0.1/", "ip_forbidden"),  # gitleaks:allow (private range must be refused)
        ("http://169.254.169.254/latest/meta-data", "ip_forbidden"),
        ("http://100.64.0.1/", "ip_forbidden"),
        ("http://0.0.0.0/", "ip_forbidden"),
        ("http://224.0.0.1/", "ip_forbidden"),
        ("http://240.0.0.1/", "ip_forbidden"),
        ("http://198.18.0.1/", "ip_forbidden"),
        ("http://192.0.2.10/", "ip_forbidden"),
        ("http://198.51.100.10/", "ip_forbidden"),
        ("http://203.0.113.10/", "ip_forbidden"),
        ("http://[::1]/", "ip_forbidden"),
        ("http://[fd00::1]/", "ip_forbidden"),
        ("http://[fe80::1]/", "ip_forbidden"),
        ("http://[2001:db8::1]/", "ip_forbidden"),
        ("http://[::ffff:127.0.0.1]/", "ip_forbidden"),
        (
            "http://[::ffff:10.0.0.1]/",  # gitleaks:allow
            "ip_forbidden",
        ),
        ("http://[64:ff9b::a00:1]/", "ip_forbidden"),
        ("http://[2002:7f00:1::]/", "ip_forbidden"),
    ],
)
def test_refused_forms(url: str, code: str) -> None:
    assert refused(url) == code


def test_url_length_is_capped() -> None:
    assert refused("http://files.example.test/" + "a" * 1100) == "too_long"


def test_owner_deny_list_applies() -> None:
    nets = (ipaddress.ip_network("8.8.8.0/24"),)
    assert refused("http://8.8.8.8/x", deny_nets=nets) == "ip_forbidden"
    assert normalize_url("http://8.8.4.4/x", deny_nets=nets).host == "8.8.4.4"
    assert refused("http://panel.mine.example/", deny_hosts=("mine.example",)) == "denied_host"
    assert refused("http://mine.example/", deny_hosts=("mine.example",)) == "denied_host"
    assert normalize_url("http://notmine.example/", deny_hosts=("mine.example",)).host


def test_normalisation() -> None:
    v = normalize_url("HTTP://Files.EXAMPLE.test:80/a/b?x=1#frag")
    assert v.url == "http://files.example.test/a/b?x=1"
    assert (v.scheme, v.host, v.port) == ("http", "files.example.test", 80)
    assert normalize_url("https://files.example.test:443").url == "https://files.example.test/"
    assert normalize_url("http://files.example.test:8080/x").url.endswith(":8080/x")
    assert normalize_url("http://8.8.4.4:81/x").url == "http://8.8.4.4:81/x"
    assert normalize_url("http://[2606:4700::1111]/x").url == "http://[2606:4700::1111]/x"
    assert normalize_url("http://bücher.example.test/").host == "xn--bcher-kva.example.test"


class TestRedirects:
    def test_relative_and_absolute_hops(self) -> None:
        base = "http://files.example.test/a/b.sh"
        assert resolve_redirect(base, "/c.sh").url == "http://files.example.test/c.sh"
        assert resolve_redirect(base, "d.sh").url == "http://files.example.test/a/d.sh"
        assert resolve_redirect(base, "https://cdn.example.test/x").scheme == "https"

    @pytest.mark.parametrize(
        "location",
        [
            "http://127.0.0.1/admin",
            "http://169.254.169.254/",
            "http://10.1.2.3:8080/",  # gitleaks:allow (private range must be refused)
            "http://[::1]/",
            "http://3232235777/",
            "http://localhost/",
            "http://intranet/x",
            "file:///etc/passwd",
            "ftp://files.example.test/x",
            "//127.0.0.1/x",
            "http://x.suckerpot_egress-proxy/",
            "http://vpn.suckerpot_samples/",
            "http://vpn.suckerpot_egress-proxy:8000/v1/publicip/ip",
        ],
    )
    def test_redirect_to_forbidden_target_is_refused(self, location: str) -> None:
        with pytest.raises(UrlRefused):
            resolve_redirect("http://files.example.test/start", location)
