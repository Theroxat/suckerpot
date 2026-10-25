"""phpMyAdmin 5.2.x login page and its response headers."""

from __future__ import annotations

import html

CSP = (
    "default-src 'self' ;script-src 'self' 'unsafe-inline' 'unsafe-eval' ;"
    "style-src 'self' 'unsafe-inline' ;img-src 'self' data: ;object-src 'none' ;"
)


def security_headers(date: str) -> list[tuple[str, str]]:
    """Headers phpMyAdmin 5.2 sends with its pages (after the PHP ones set by the script)."""
    return [
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "same-origin"),
        ("Content-Security-Policy", CSP),
        ("X-Content-Security-Policy", CSP),
        ("X-XSS-Protection", "1; mode=block"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Permitted-Cross-Domain-Policies", "none"),
        ("X-Robots-Tag", "noindex, nofollow"),
        (
            "Cache-Control",
            "no-store, no-cache, must-revalidate,  pre-check=0, post-check=0, max-age=0",
        ),
        ("Pragma", "no-cache"),
        ("Expires", date),
        ("Last-Modified", date),
    ]


def login_page(version: str, token: str, *, error: str = "", prefix: str = "") -> str:
    err = ""
    if error:
        err = (
            '<div class="alert alert-danger" role="alert"><img src="themes/dot.gif" title="" '
            f'alt="" class="icon ic_s_error"> {html.escape(error)}</div>'
        )
    v = version
    return f"""<!doctype html>
<html lang="en" dir="ltr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="referrer" content="same-origin">
  <meta name="robots" content="noindex,nofollow">
  <meta http-equiv="X-UA-Compatible" content="IE=Edge">
  <style id="cfs-style">html{{display: none;}}</style>
  <link rel="icon" href="favicon.ico" type="image/x-icon">
  <link rel="shortcut icon" href="favicon.ico" type="image/x-icon">
  <link rel="stylesheet" type="text/css" href="./themes/pmahomme/css/theme.css?v={v}">
  <title>phpMyAdmin</title>
  <script data-cfasync="false" type="text/javascript" src="js/vendor/jquery/jquery.min.js?v={v}"></script>
  <script data-cfasync="false" type="text/javascript" src="js/vendor/jquery/jquery-migrate.min.js?v={v}"></script>
  <script data-cfasync="false" type="text/javascript" src="js/vendor/sprintf.js?v={v}"></script>
  <script data-cfasync="false" type="text/javascript" src="js/vendor/jquery/jquery-ui.min.js?v={v}"></script>
  <script data-cfasync="false" type="text/javascript" src="js/dist/menu_resizer.js?v={v}"></script>
  <script data-cfasync="false" type="text/javascript" src="js/dist/cross_framing_protection.js?v={v}"></script>
  <script data-cfasync="false" type="text/javascript" src="index.php?route=/messages&l=en&v={v}"></script>
  <script data-cfasync="false" type="text/javascript" src="js/dist/login.js?v={v}"></script>
  <noscript><style>html{{display:block}}</style></noscript>
</head>
<body id="loginform">
  <div class="container">
    <a href="./url.php?url=https%3A%2F%2Fwww.phpmyadmin.net%2F" target="_blank" rel="noopener noreferrer" class="logo">
      <img src="./themes/pmahomme/img/logo_right.png" id="imLogo" name="imLogo" alt="phpMyAdmin" border="0">
    </a>
    <h1>Welcome to <bdo dir="ltr" lang="en">phpMyAdmin</bdo></h1>
    <noscript>
      <div class="alert alert-danger" role="alert"><img src="themes/dot.gif" title="" alt="" class="icon ic_s_error"> Javascript must be enabled past this point!</div>
    </noscript>
    <div class="hide js-show">
      <form method="post" action="index.php?route=/" class="disableAjax">
        <input type="hidden" name="set_session" value="{html.escape(token[:32])}">
        <div class="mb-3">
          <label for="languageSelect"><img src="themes/dot.gif" title="" alt="Language" class="icon ic_s_lang"> Language</label>
          <select name="lang" class="autosubmit" lang="en" dir="ltr" id="languageSelect">
            <option value="en" selected>English</option>
            <option value="de">Deutsch - German</option>
            <option value="fr">Fran&ccedil;ais - French</option>
            <option value="es">Espa&ntilde;ol - Spanish</option>
          </select>
        </div>
      </form>
    </div>
    {err}
    <form method="post" id="login_form" action="index.php?route=/" name="login_form" class="disableAjax hide js-show">
      <fieldset>
        <legend>Log in<a href="./doc/html/index.html" target="documentation"><img src="themes/dot.gif" title="phpMyAdmin documentation" alt="phpMyAdmin documentation" class="icon ic_b_help"></a></legend>
        <div class="mb-3">
          <label for="input_username">Username:</label>
          <input type="text" name="pma_username" id="input_username" value="" size="24" class="textfield" autocomplete="username">
        </div>
        <div class="mb-3">
          <label for="input_password">Password:</label>
          <input type="password" name="pma_password" id="input_password" value="" size="24" class="textfield" autocomplete="current-password">
        </div>
        <input type="hidden" name="server" value="1">
      </fieldset>
      <fieldset class="tblFooters">
        <input class="btn btn-primary" value="Log in" type="submit" id="input_go">
        <input type="hidden" name="set_session" value="{html.escape(token[:32])}">
        <input type="hidden" name="token" value="{html.escape(token)}">
      </fieldset>
    </form>
  </div>
</body>
</html>
"""
