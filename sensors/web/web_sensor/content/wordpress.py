"""WordPress (Twenty Twenty-Four) pages: home, posts, login, REST API, feeds, readme."""

from __future__ import annotations

import html
import json
from datetime import UTC, datetime

from web_sensor.profile import Post, Profile, WPUser

THEME_VERSION = "1.3"


def fmt_date(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, UTC)
    return f"{dt:%B} {dt.day}, {dt.year}"


def iso_date(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def php_json(value: object) -> str:
    """json_encode() as PHP writes it by default: escaped slashes, compact."""
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).replace("/", "\\/")


_GLOBAL_STYLES = (
    ":root{--wp--preset--aspect-ratio--square: 1;--wp--preset--aspect-ratio--4-3: 4/3;"
    "--wp--preset--aspect-ratio--3-4: 3/4;--wp--preset--aspect-ratio--3-2: 3/2;"
    "--wp--preset--aspect-ratio--2-3: 2/3;--wp--preset--aspect-ratio--16-9: 16/9;"
    "--wp--preset--aspect-ratio--9-16: 9/16;--wp--preset--color--black: #000000;"
    "--wp--preset--color--cyan-bluish-gray: #abb8c3;--wp--preset--color--white: #ffffff;"
    "--wp--preset--color--pale-pink: #f78da7;--wp--preset--color--vivid-red: #cf2e2e;"
    "--wp--preset--color--base: #ffffff;--wp--preset--color--contrast: #000000;"
    "--wp--preset--color--accent-1: #FFEE58;--wp--preset--color--accent-2: #F6CFF4;"
    "--wp--preset--color--accent-3: #503AA8;--wp--preset--color--accent-4: #686868;"
    "--wp--preset--color--accent-5: #FBFAF3;--wp--preset--color--accent-6: #00000033;"
    "--wp--preset--font-size--small: clamp(0.875rem, 0.875rem + ((1vw - 0.2rem) * 0.227), 1rem);"
    "--wp--preset--font-size--medium: clamp(1rem, 1rem + ((1vw - 0.2rem) * 0.227), 1.125rem);"
    "--wp--preset--font-size--large: clamp(1.75rem, 1.75rem + ((1vw - 0.2rem) * 0.227), 1.875rem);"
    "--wp--preset--font-size--x-large: 2.25rem;--wp--preset--font-family--system-font: "
    '-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,'
    '"Helvetica Neue",sans-serif;--wp--preset--spacing--20: 10px;--wp--preset--spacing--30: '
    "20px;--wp--preset--spacing--40: 30px;--wp--preset--spacing--50: clamp(30px, 5vw, 50px);"
    "--wp--preset--spacing--60: clamp(30px, 7vw, 70px);--wp--preset--spacing--70: "
    "clamp(50px, 7vw, 90px);--wp--preset--spacing--80: clamp(70px, 10vw, 140px);}"
    ":where(body) { margin: 0; }.wp-site-blocks { padding-top: var(--wp--style--root--padding-top); "
    "padding-bottom: var(--wp--style--root--padding-bottom); }body { background-color: "
    "var(--wp--preset--color--base); color: var(--wp--preset--color--contrast); "
    "font-family: var(--wp--preset--font-family--system-font); font-size: "
    "var(--wp--preset--font-size--large); line-height: 1.5; }a:where(:not(.wp-element-button)) "
    "{ color: var(--wp--preset--color--contrast); text-decoration: underline; }"
)


def _head(base: str, title: str, p: Profile, wp: str, body_class: str, extra_head: str = "") -> str:
    return f"""<!DOCTYPE html>
<html lang="en-US">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name='robots' content='max-image-preview:large' />
<title>{title}</title>
<link rel="alternate" type="application/rss+xml" title="{p.site_title} &raquo; Feed" href="{base}/feed/" />
<link rel="alternate" type="application/rss+xml" title="{p.site_title} &raquo; Comments Feed" href="{base}/comments/feed/" />
<script>
window._wpemojiSettings = {{"baseUrl":"https:\\/\\/s.w.org\\/images\\/core\\/emoji\\/15.1.0\\/72x72\\/","ext":".png","svgUrl":"https:\\/\\/s.w.org\\/images\\/core\\/emoji\\/15.1.0\\/svg\\/","svgExt":".svg","source":{{"concatemoji":"{base.replace("/", "\\/")}\\/wp-includes\\/js\\/wp-emoji-release.min.js?ver={wp}"}}}};
/*! This file is auto-generated */
!function(i,n){{var o,s,e;function c(e){{try{{var t={{supportTests:e,timestamp:(new Date).valueOf()}};sessionStorage.setItem(o,JSON.stringify(t))}}catch(e){{}}}}}}(window,document);
</script>
<style id='wp-emoji-styles-inline-css'>
img.wp-smiley, img.emoji {{ display: inline !important; border: none !important; box-shadow: none !important; height: 1em !important; width: 1em !important; margin: 0 0.07em !important; vertical-align: -0.1em !important; background: none !important; padding: 0 !important;}}
</style>
<link rel='stylesheet' id='wp-block-library-css' href='{base}/wp-includes/css/dist/block-library/style.min.css?ver={wp}' media='all' />
<style id='global-styles-inline-css'>
{_GLOBAL_STYLES}
</style>
<link rel='stylesheet' id='twentytwentyfour-style-css' href='{base}/wp-content/themes/twentytwentyfour/style.css?ver={THEME_VERSION}' media='all' />
<link rel="https://api.w.org/" href="{base}/wp-json/" /><link rel="EditURI" type="application/rsd+xml" title="RSD" href="{base}/xmlrpc.php?rsd" />
<meta name="generator" content="WordPress {wp}" />
{extra_head}</head>

<body class="{body_class} wp-embed-responsive wp-theme-twentytwentyfour">

<div class="wp-site-blocks"><header class="wp-block-template-part">
<div class="wp-block-group alignfull is-layout-constrained wp-block-group-is-layout-constrained" style="padding-top:var(--wp--preset--spacing--30);padding-bottom:var(--wp--preset--spacing--30)">
<div class="wp-block-group alignwide is-content-justification-space-between is-layout-flex wp-container-core-group-is-layout-1 wp-block-group-is-layout-flex">
<p class="wp-block-site-title"><a href="{base}/" target="_self" rel="home">{p.site_title}</a></p>
<nav class="is-responsive items-justified-right wp-block-navigation is-content-justification-right is-layout-flex wp-block-navigation-is-layout-flex" aria-label="Navigation"><ul class="wp-block-navigation__container is-responsive items-justified-right wp-block-navigation"><li class="wp-block-navigation-item wp-block-navigation-link"><a class="wp-block-navigation-item__content" href="{base}/"><span class="wp-block-navigation-item__label">Home</span></a></li><li class="wp-block-navigation-item wp-block-navigation-link"><a class="wp-block-navigation-item__content" href="{base}/sample-page/"><span class="wp-block-navigation-item__label">Sample Page</span></a></li></ul></nav>
</div>
</div>
</header>
"""


def _footer(base: str, p: Profile, wp: str) -> str:
    return f"""<footer class="wp-block-template-part">
<div class="wp-block-group has-global-padding is-layout-constrained wp-block-group-is-layout-constrained" style="padding-top:var(--wp--preset--spacing--60);padding-bottom:var(--wp--preset--spacing--50)">
<div class="wp-block-group alignfull is-content-justification-space-between is-layout-flex wp-block-group-is-layout-flex">
<p class="has-small-font-size">{p.site_title} &#8211; {p.tagline}</p>
<p class="has-small-font-size">Proudly powered by <a href="https://wordpress.org" rel="nofollow">WordPress</a></p>
</div>
</div>
</footer>
</div><script type="speculationrules">
{{"prefetch":[{{"source":"document","where":{{"and":[{{"href_matches":"\\/*"}},{{"not":{{"href_matches":["\\/wp-*.php","\\/wp-admin\\/*","\\/wp-content\\/uploads\\/*","\\/wp-content\\/*","\\/wp-content\\/plugins\\/*","\\/wp-content\\/themes\\/twentytwentyfour\\/*","\\/*\\\\?(.+)"]}}}}]}},"eagerness":"conservative"}}]}}
</script>
</body>
</html>
"""


def _post_block(base: str, post: Post, p: Profile) -> str:
    author = p.users[0].display
    return f"""<li class="wp-block-post post-{post.id} post type-post status-publish format-standard hentry category-uncategorized">
<div class="wp-block-group is-layout-flow wp-block-group-is-layout-flow" style="padding-top:var(--wp--preset--spacing--20);padding-bottom:var(--wp--preset--spacing--20)">
<h2 class="wp-block-post-title has-x-large-font-size"><a href="{base}/{post.slug}/" target="_self" >{post.title}</a></h2>
<div class="entry-content wp-block-post-content is-layout-flow wp-block-post-content-is-layout-flow"><p>{html.escape(post.body)}</p></div>
<div class="wp-block-group is-layout-flex wp-block-group-is-layout-flex"><div class="wp-block-post-date"><time datetime="{iso_date(post.ts)}"><a href="{base}/{post.slug}/">{fmt_date(post.ts)}</a></time></div>
<div class="wp-block-post-author-name"><a href="{base}/author/{p.users[0].login}/" target="_self" class="wp-block-post-author-name__link">{html.escape(author)}</a></div></div>
</div>
</li>
"""


def home_page(base: str, p: Profile, wp: str) -> str:
    items = "".join(_post_block(base, post, p) for post in p.posts)
    return (
        _head(base, f"{p.site_title} &#8211; {p.tagline}", p, wp, "home blog")
        + f"""<main class="wp-block-group has-global-padding is-layout-constrained wp-block-group-is-layout-constrained" style="margin-top:var(--wp--preset--spacing--60)">
<div class="wp-block-query is-layout-flow wp-block-query-is-layout-flow"><ul class="alignfull wp-block-post-template is-layout-flow wp-block-post-template-is-layout-flow">
{items}</ul></div>
</main>
"""
        + _footer(base, p, wp)
    )


def post_page(base: str, post: Post, p: Profile, wp: str) -> str:
    return (
        _head(
            base,
            f"{post.title} &#8211; {p.site_title}",
            p,
            wp,
            f"post-template-default single single-post postid-{post.id} single-format-standard",
        )
        + f"""<main class="wp-block-group has-global-padding is-layout-constrained wp-block-group-is-layout-constrained" style="margin-top:var(--wp--preset--spacing--60)">
<article class="post-{post.id} post type-post status-publish format-standard hentry">
<h1 class="wp-block-post-title">{post.title}</h1>
<div class="wp-block-post-date"><time datetime="{iso_date(post.ts)}">{fmt_date(post.ts)}</time></div>
<div class="entry-content wp-block-post-content is-layout-constrained wp-block-post-content-is-layout-constrained"><p>{html.escape(post.body)}</p></div>
</article>
</main>
"""
        + _footer(base, p, wp)
    )


def listing_page(base: str, heading: str, p: Profile, wp: str, posts: list[Post], cls: str) -> str:
    items = "".join(_post_block(base, post, p) for post in posts)
    if not items:
        items = "<li><p>No results were found.</p></li>"
    return (
        _head(base, f"{heading} &#8211; {p.site_title}", p, wp, cls)
        + f"""<main class="wp-block-group has-global-padding is-layout-constrained wp-block-group-is-layout-constrained" style="margin-top:var(--wp--preset--spacing--60)">
<h1 class="wp-block-query-title">{heading}</h1>
<div class="wp-block-query is-layout-flow wp-block-query-is-layout-flow"><ul class="alignfull wp-block-post-template is-layout-flow wp-block-post-template-is-layout-flow">
{items}</ul></div>
</main>
"""
        + _footer(base, p, wp)
    )


def not_found_page(base: str, p: Profile, wp: str) -> str:
    return (
        _head(base, f"Page not found &#8211; {p.site_title}", p, wp, "error404")
        + f"""<main class="wp-block-group has-global-padding is-layout-constrained wp-block-group-is-layout-constrained" style="margin-top:var(--wp--preset--spacing--60)">
<h1 class="wp-block-heading">Page not found</h1>
<p>The page you are looking for doesn't exist or has been moved. Please check the address or return to the <a href="{base}/">home page</a>.</p>
<form role="search" method="get" action="{base}/" class="wp-block-search__button-outside wp-block-search__text-button wp-block-search"><label class="wp-block-search__label" for="wp-block-search__input-1" >Search</label><div class="wp-block-search__inside-wrapper " ><input class="wp-block-search__input" id="wp-block-search__input-1" placeholder="" value="" type="search" name="s" required /><button aria-label="Search" class="wp-block-search__button wp-element-button" type="submit" >Search</button></div></form>
</main>
"""
        + _footer(base, p, wp)
    )


def login_page(
    base: str, p: Profile, wp: str, *, error: str = "", user: str = "", notice: str = ""
) -> str:
    msgs = ""
    if error:
        msgs += f'<div id="login_error" class="notice notice-error"><p>{error}</p></div>\n'
    if notice:
        msgs += f'<p class="message">{notice}</p>\n'
    return f"""<!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Log In &lsaquo; {p.site_title} &#8212; WordPress</title>
<meta name='robots' content='max-image-preview:large, noindex, noarchive' />
<link rel='stylesheet' id='dashicons-css' href='{base}/wp-includes/css/dashicons.min.css?ver={wp}' media='all' />
<link rel='stylesheet' id='buttons-css' href='{base}/wp-includes/css/buttons.min.css?ver={wp}' media='all' />
<link rel='stylesheet' id='forms-css' href='{base}/wp-admin/css/forms.min.css?ver={wp}' media='all' />
<link rel='stylesheet' id='l10n-css' href='{base}/wp-admin/css/l10n.min.css?ver={wp}' media='all' />
<link rel='stylesheet' id='login-css' href='{base}/wp-admin/css/login.min.css?ver={wp}' media='all' />
<meta name='referrer' content='strict-origin-when-cross-origin' />
<meta name="viewport" content="width=device-width" />
</head>
<body class="login no-js login-action-login wp-core-ui  locale-en-us">
<script>
document.body.className = document.body.className.replace('no-js','js');
</script>
<div id="login">
<h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
{msgs}
<form name="loginform" id="loginform" action="{base}/wp-login.php" method="post">
<p>
<label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" class="input" value="{html.escape(user)}" size="20" autocapitalize="off" autocomplete="username" required="required" />
</p>
<div class="user-pass-wrap">
<label for="user_pass">Password</label>
<div class="wp-pwd">
<input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password" spellcheck="false" required="required" />
<button type="button" class="button button-secondary wp-hide-pw hide-if-no-js" data-toggle="0" aria-label="Show password">
<span class="dashicons dashicons-visibility" aria-hidden="true"></span>
</button>
</div>
</div>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever"  /> <label for="rememberme">Remember Me</label></p>
<p class="submit">
<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
<input type="hidden" name="redirect_to" value="{base}/wp-admin/" />
<input type="hidden" name="testcookie" value="1" />
</p>
</form>
<p id="nav">
<a class="wp-login-lost-password" href="{base}/wp-login.php?action=lostpassword">Lost your password?</a>
</p>
<script>
function wp_attempt_focus() {{setTimeout( function() {{try {{d = document.getElementById( "user_login" );d.focus(); d.select();}} catch( er ) {{}}}}, 200);}}
wp_attempt_focus();
if ( typeof wpOnload === 'function' ) {{ wpOnload(); }}
</script>
<p id="backtoblog">
<a href="{base}/">&larr; Go to {p.site_title}</a>
</p>
</div>
<script src="{base}/wp-includes/js/jquery/jquery.min.js?ver=3.7.1" id="jquery-core-js"></script>
<div class="clear"></div>
</body>
</html>
"""


def lost_password_page(base: str, p: Profile, wp: str) -> str:
    return login_page(
        base,
        p,
        wp,
        notice="Please enter your username or email address. You will receive an email message with instructions on how to reset your password.",
    ).replace("login-action-login", "login-action-lostpassword")


def login_error(base: str, p: Profile, username: str, password: str) -> str:
    """WordPress 6.8 error text for a failed login (the user-enumeration behaviour included)."""
    lost = f'<a href="{base}/wp-login.php?action=lostpassword">Lost your password?</a>'
    if not username:
        return "<strong>Error:</strong> The username field is empty."
    if not password:
        return "<strong>Error:</strong> The password field is empty."
    esc = html.escape(username)
    if any(u.login.lower() == username.lower() for u in p.users):
        return (
            f"<strong>Error:</strong> The password you entered for the username <strong>{esc}</strong>"
            f" is incorrect. {lost}"
        )
    return (
        f"<strong>Error:</strong> The username <strong>{esc}</strong> is not registered on this "
        "site. If you are unsure of your username, try your email address instead."
    )


def _user_json(base: str, u: WPUser) -> dict[str, object]:
    av = f"https://secure.gravatar.com/avatar/{u.email_hash}?s=%d&d=mm&r=g"
    return {
        "id": u.id,
        "name": u.display,
        "url": "",
        "description": "",
        "link": f"{base}/author/{u.login}/",
        "slug": u.login,
        "avatar_urls": {"24": av % 24, "48": av % 48, "96": av % 96},
        "meta": [],
        "_links": {
            "self": [
                {"href": f"{base}/wp-json/wp/v2/users/{u.id}", "targetHints": {"allow": ["GET"]}}
            ],
            "collection": [{"href": f"{base}/wp-json/wp/v2/users"}],
        },
    }


def rest_users(base: str, p: Profile) -> str:
    return php_json([_user_json(base, u) for u in p.users])


def rest_user(base: str, u: WPUser) -> str:
    return php_json(_user_json(base, u))


def rest_index(base: str, p: Profile, wp: str) -> str:
    routes = {
        "/": {
            "namespace": "",
            "methods": ["GET"],
            "endpoints": [
                {"methods": ["GET"], "args": {"context": {"default": "view", "required": False}}}
            ],
            "_links": {"self": [{"href": f"{base}/wp-json/"}]},
        },
        "/wp/v2/posts": {
            "namespace": "wp/v2",
            "methods": ["GET", "POST"],
            "_links": {"self": [{"href": f"{base}/wp-json/wp/v2/posts"}]},
        },
        "/wp/v2/pages": {
            "namespace": "wp/v2",
            "methods": ["GET", "POST"],
            "_links": {"self": [{"href": f"{base}/wp-json/wp/v2/pages"}]},
        },
        "/wp/v2/users": {
            "namespace": "wp/v2",
            "methods": ["GET", "POST"],
            "_links": {"self": [{"href": f"{base}/wp-json/wp/v2/users"}]},
        },
    }
    doc = {
        "name": p.site_title.replace("&amp;", "&"),
        "description": p.tagline,
        "url": base,
        "home": base,
        "gmt_offset": "0",
        "timezone_string": "",
        "page_for_posts": 0,
        "page_on_front": 0,
        "show_on_front": "posts",
        "namespaces": ["oembed/1.0", "wp/v2", "wp-site-health/v1", "wp-block-editor/v1"],
        "authentication": {
            "application-passwords": {
                "endpoints": {"authorization": f"{base}/wp-admin/authorize-application.php"}
            }
        },
        "routes": routes,
        "site_logo": 0,
        "site_icon": 0,
        "site_icon_url": "",
        "_links": {"help": [{"href": "https://developer.wordpress.org/rest-api/"}]},
    }
    return php_json(doc)


def posts_json(base: str, p: Profile) -> str:
    out = []
    for post in p.posts:
        out.append(
            {
                "id": post.id,
                "date": iso_date(post.ts).replace("+00:00", ""),
                "date_gmt": iso_date(post.ts).replace("+00:00", ""),
                "guid": {"rendered": f"{base}/?p={post.id}"},
                "slug": post.slug,
                "status": "publish",
                "type": "post",
                "link": f"{base}/{post.slug}/",
                "title": {"rendered": post.title},
                "author": 1,
                "comment_status": "open",
            }
        )
    return php_json(out)


def rest_404() -> str:
    return php_json(
        {
            "code": "rest_no_route",
            "message": "No route was found matching the URL and request method.",
            "data": {"status": 404},
        }
    )


def rest_user_forbidden() -> str:
    return php_json(
        {
            "code": "rest_user_cannot_view",
            "message": "Sorry, you are not allowed to list users.",
            "data": {"status": 401},
        }
    )


def robots_txt(base: str) -> str:
    return f"User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n\nSitemap: {base}/wp-sitemap.xml\n"


def sitemap_xml(base: str, p: Profile) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<?xml-stylesheet type="text/xsl" href="' + base + '/wp-sitemap.xsl" ?>'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"<sitemap><loc>{base}/wp-sitemap-posts-post-1.xml</loc></sitemap>"
        f"<sitemap><loc>{base}/wp-sitemap-posts-page-1.xml</loc></sitemap>"
        f"<sitemap><loc>{base}/wp-sitemap-users-1.xml</loc></sitemap>"
        "</sitemapindex>"
    )


def rsd_xml(base: str, wp: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<rsd version="1.0" xmlns="http://archipelago.phrasewise.com/rsd">\n'
        "\t<service>\n\t\t<engineName>WordPress</engineName>\n\t\t<engineLink>https://wordpress.org/</engineLink>\n"
        f"\t\t<homePageLink>{base}/</homePageLink>\n\t\t<apis>\n"
        f'\t\t\t<api name="WordPress" blogID="1" preferred="true" apiLink="{base}/xmlrpc.php" />\n'
        f'\t\t\t<api name="Movable Type" blogID="1" preferred="false" apiLink="{base}/xmlrpc.php" />\n'
        f'\t\t\t<api name="MetaWeblog" blogID="1" preferred="false" apiLink="{base}/xmlrpc.php" />\n'
        f'\t\t\t<api name="Blogger" blogID="1" preferred="false" apiLink="{base}/xmlrpc.php" />\n'
        f'\t\t\t<api name="WP-API" blogID="1" preferred="false" apiLink="{base}/wp-json/" />\n'
        "\t\t</apis>\n\t</service>\n</rsd>\n"
    )


def feed_xml(base: str, p: Profile, wp: str) -> str:
    items = "".join(
        f"\t<item>\n\t\t<title>{post.title}</title>\n\t\t<link>{base}/{post.slug}/</link>\n"
        f"\t\t<dc:creator><![CDATA[{p.users[0].display}]]></dc:creator>\n"
        f"\t\t<pubDate>{datetime.fromtimestamp(post.ts, UTC):%a, %d %b %Y %H:%M:%S} +0000</pubDate>\n"
        f'\t\t<guid isPermaLink="false">{base}/?p={post.id}</guid>\n'
        f"\t\t<description><![CDATA[{html.escape(post.body)}]]></description>\n\t</item>\n"
        for post in p.posts
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"\n'
        '\txmlns:content="http://purl.org/rss/1.0/modules/content/"\n'
        '\txmlns:dc="http://purl.org/dc/elements/1.1/"\n'
        '\txmlns:atom="http://www.w3.org/2005/Atom"\n'
        "\t>\n\n<channel>\n"
        f"\t<title>{p.site_title}</title>\n"
        f'\t<atom:link href="{base}/feed/" rel="self" type="application/rss+xml" />\n'
        f"\t<link>{base}</link>\n\t<description>{p.tagline}</description>\n"
        f"\t<lastBuildDate>{datetime.fromtimestamp(p.posts[0].ts, UTC):%a, %d %b %Y %H:%M:%S} +0000</lastBuildDate>\n"
        "\t<language>en-US</language>\n\t<sy:updatePeriod>hourly</sy:updatePeriod>\n"
        "\t<sy:updateFrequency>1</sy:updateFrequency>\n"
        f"\t<generator>https://wordpress.org/?v={wp}</generator>\n"
        f"{items}</channel>\n</rss>\n"
    )


def readme_html(wp: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
	<meta name="viewport" content="width=device-width" />
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<title>WordPress &#8250; ReadMe</title>
	<link rel="stylesheet" href="wp-admin/css/install.css?ver=20100228" type="text/css" />
</head>
<body>
<h1 id="logo">
	<a href="https://wordpress.org/"><img alt="WordPress" src="wp-admin/images/wordpress-logo.png" /></a>
</h1>
<p style="text-align: center">Semantic Personal Publishing Platform</p>

<h2>First Things First</h2>
<p>Welcome. WordPress is a very special project to me. Every developer and contributor adds something unique to the mix, and together we create something beautiful that I&#8217;m proud to be a part of. Thousands of hours have gone into WordPress, and we&#8217;re dedicated to making it better every day. Thank you for making it part of your world.</p>
<p style="text-align: right">&#8212; Matt Mullenweg</p>

<h2>Installation: Famous 5-minute install</h2>
<ol>
	<li>Unzip the package in an empty directory and upload everything.</li>
	<li>Open <span class="file"><a href="wp-admin/install.php">wp-admin/install.php</a></span> in your browser. It will take you through the process to set up a <code>wp-config.php</code> file with your database connection details.
		<ol>
			<li>If for some reason this doesn&#8217;t work, don&#8217;t worry. It doesn&#8217;t work on all web hosts. Open up <code>wp-config-sample.php</code> with a text editor like WordPad or similar and fill in your database connection details.</li>
			<li>Save the file as <code>wp-config.php</code> and upload it.</li>
			<li>Open <span class="file"><a href="wp-admin/install.php">wp-admin/install.php</a></span> in your browser.</li>
		</ol>
	</li>
	<li>Once the configuration file is set up, the installer will set up the tables needed for your site. If there is an error, double check your <code>wp-config.php</code> file, and try again. If it fails again, please go to the <a href="https://wordpress.org/support/forums/">WordPress support forums</a> with as much data as you can gather.</li>
	<li><strong>If you did not enter a password, note the password given to you.</strong> If you did not provide a username, it will be <code>admin</code>.</li>
	<li>The installer should then send you to the <a href="wp-login.php">login page</a>. Sign in with the username and password you chose during the installation. If a password was generated for you, you can then click on &#8220;Profile&#8221; to change the password.</li>
</ol>

<h2>System Requirements</h2>
<ul>
	<li><a href="https://www.php.net/">PHP</a> version <strong>7.2.24</strong> or greater.</li>
	<li><a href="https://www.mysql.com/">MySQL</a> version <strong>5.5.5</strong> or greater.</li>
</ul>

<h2>Recommendations</h2>
<ul>
	<li><a href="https://www.php.net/">PHP</a> version <strong>7.4</strong> or greater.</li>
	<li><a href="https://www.mysql.com/">MySQL</a> version <strong>8.0</strong> or greater OR <a href="https://mariadb.org/">MariaDB</a> version <strong>10.5</strong> or greater.</li>
	<li>The <a href="https://httpd.apache.org/docs/2.2/mod/mod_rewrite.html">mod_rewrite</a> Apache module.</li>
	<li><a href="https://wordpress.org/news/2016/12/moving-toward-ssl/">HTTPS</a> support.</li>
	<li>A link to <a href="https://wordpress.org/">wordpress.org</a> on your site.</li>
</ul>

<h2>Online Resources</h2>
<p>If you have any questions that aren&#8217;t addressed in this document, please take advantage of WordPress&#8217; numerous online resources:</p>
<dl>
	<dt><a href="https://wordpress.org/documentation/">WordPress Documentation</a></dt>
		<dd>The WordPress documentation is a collection of lessons, tutorials, and other helpful resources.</dd>
	<dt><a href="https://wordpress.org/news/">WordPress Blog</a></dt>
		<dd>This is where you&#8217;ll find the latest updates and news related to WordPress.</dd>
	<dt><a href="https://wordpress.org/support/forums/">WordPress Support Forums</a></dt>
		<dd>If you&#8217;ve looked everywhere and still can&#8217;t find an answer, the support forums are very active and have a large community ready to help.</dd>
</dl>

<h2>Final Notes</h2>
<ul>
	<li>If you have any suggestions, ideas, or comments, or if you (gasp!) found a bug, join us in the <a href="https://wordpress.org/support/forums/">Support Forums</a>.</li>
	<li>WordPress has a robust plugin API that makes extending the code easy. If you are a developer interested in utilizing this, see the <a href="https://developer.wordpress.org/plugins/">Plugin Developer Handbook</a>.</li>
</ul>

<h2>Share the Love</h2>
<p>WordPress has no multi-million dollar marketing campaign or celebrity sponsors, but we do have something even better&#8212;you. If you enjoy WordPress please consider telling a friend, setting it up for someone less knowledgable than yourself, or writing the author of a media article that overlooks us.</p>

<p style="text-align: right">&#8212; Matt Mullenweg</p>
<!-- Version {wp} -->
</body>
</html>
"""


LICENSE_TXT = """WordPress - Web publishing software

Copyright 2011-2025 by the contributors

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""


THEME_STYLE_CSS = f"""/*
Theme Name: Twenty Twenty-Four
Theme URI: https://wordpress.org/themes/twentytwentyfour/
Author: the WordPress team
Author URI: https://wordpress.org
Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collection of templates and patterns tailor to different needs, such as presenting a business, blogging and writing or showcasing work as a photographer.
Requires at least: 6.4
Tested up to: 6.7
Requires PHP: 7.0
Version: {THEME_VERSION}
License: GNU General Public License v2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
Text Domain: twentytwentyfour
Tags: one-column, custom-colors, custom-menu, custom-logo, editor-style, featured-images, full-site-editing, block-patterns, rtl-language-support, sticky-post, threaded-comments, translation-ready, wide-blocks, block-styles, style-variations, accessibility-ready, blog, portfolio, news
*/

/*
 * Font smoothing.
 */
body {{
	-moz-osx-font-smoothing: grayscale;
	-webkit-font-smoothing: antialiased;
}}

/*
 * Text and navigation link styles.
 */
a {{
	text-decoration-thickness: 1px !important;
	text-underline-offset: .1em;
}}
"""

THEME_README = f"""=== Twenty Twenty-Four ===
Contributors: wordpressdotorg
Requires at least: 6.4
Tested up to: 6.7
Requires PHP: 7.0
Stable tag: {THEME_VERSION}
License: GNU General Public License v2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

== Description ==

Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website.

== Changelog ==

= {THEME_VERSION} =
* Released: November 7, 2024
"""

AKISMET_README = """=== Akismet Anti-spam: Spam Protection ===
Contributors: automattic, akismetantispam
Tags: comments, spam, antispam, anti-spam, contact form
Requires at least: 5.8
Tested up to: 6.7
Stable tag: 5.3.5
Requires PHP: 7.2
License: GPLv2 or later

The best anti-spam protection to block spam comments and spam in a contact form.
"""
