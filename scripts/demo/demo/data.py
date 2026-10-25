"""Static lists used to make the synthetic attacks look real. Kept small on purpose."""

from __future__ import annotations

FAKE_HOSTNAME = "srv-web01"

# (username, password) pairs, most common first. Sampled with a heavy head.
SSH_CREDS: list[tuple[str, str]] = [
    ("root", "123456"),
    ("root", "password"),
    ("admin", "admin"),
    ("ubuntu", "ubuntu"),
    ("pi", "raspberry"),
    ("root", "root"),
    ("root", "admin"),
    ("user", "user"),
    ("test", "test"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
    ("git", "git"),
    ("ubnt", "ubnt"),
    ("root", "toor"),
    ("admin", "123456"),
    ("debian", "debian"),
    ("ftpuser", "ftpuser"),
    ("root", "Passw0rd"),
    ("deploy", "deploy"),
    ("guest", "guest"),
    ("root", "qwerty"),
    ("root", "1q2w3e4r"),
    ("admin", "password"),
    ("hadoop", "hadoop"),
    ("minecraft", "minecraft"),
    ("root", "changeme"),
    ("support", "support"),
    ("vagrant", "vagrant"),
    ("root", "P@ssw0rd"),
    ("ec2-user", "ec2-user"),
]
SSH_EXTRA_USERS = [
    "root",
    "admin",
    "ubuntu",
    "user",
    "test",
    "dev",
    "www",
    "nginx",
    "mysql",
    "jenkins",
]
SSH_EXTRA_PASSWORDS = [
    "123456", "12345678", "111111", "000000", "letmein", "welcome", "abc123", "dragon",
    "master", "monkey", "football", "iloveyou", "pass", "1234", "server", "Admin123",
]  # fmt: skip

TELNET_CREDS: list[tuple[str, str]] = [
    ("root", "xc3511"),
    ("root", "vizxv"),
    ("admin", "admin"),
    ("root", "admin"),
    ("root", "888888"),
    ("root", "default"),
    ("root", "juantech"),
    ("admin", "1234"),
    ("support", "support"),
    ("user", "user"),
    ("root", "12345"),
    ("guest", "12345"),
    ("admin", "password"),
    ("root", "root"),
    ("default", ""),
    ("root", "klv123"),
    ("admin", "smcadmin"),
    ("root", "hi3518"),
    ("root", "ikwb"),
    ("Administrator", "admin"),
]

RDP_USERS = [
    "administrator", "admin", "user", "test", "guest", "scanner", "john", "sql", "backup",
    "server", "office", "ts", "support", "user1",
]  # fmt: skip

SSH_CLIENTS = [
    "SSH-2.0-libssh_0.9.6",
    "SSH-2.0-libssh2_1.10.0",
    "SSH-2.0-Go",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    "SSH-2.0-paramiko_3.4.0",
    "SSH-2.0-PuTTY_Release_0.78",
    "SSH-2.0-AsyncSSH_2.14.2",
    "SSH-2.0-JSCH-0.1.54",
    "SSH-2.0-OpenSSH_7.4",
    "SSH-2.0-russh_0.44.0",
]

RECON_COMMANDS = [
    "uname -a",
    "uname -s -v -n -r -m",
    "cat /proc/cpuinfo | grep name | wc -l",
    "cat /proc/cpuinfo | grep 'model name' | head -n 1",
    "nproc",
    "free -m",
    "w",
    "id",
    "whoami",
    "uptime",
    "cat /etc/issue",
    "cat /etc/os-release",
    "lscpu | grep Model",
    "which curl wget python3",
    "crontab -l",
    "ps aux | head -n 20",
    "ls -la /tmp",
    "df -h",
    "last -n 5",
    "ifconfig",
]

HUMAN_COMMANDS = [
    "ls",
    "pwd",
    "cd /var/www",
    "ls -la",
    "cat /etc/passwd",
    "history",
    "sudo -l",
    "cat .bash_history",
    "netstat -tlnp",
    "ps aux",
    "cat /var/www/html/config.php",
    "exit",
]

SSH_CANNED: dict[str, str] = {
    "uname -a": f"Linux {FAKE_HOSTNAME} 5.15.0-125-generic #135-Ubuntu SMP x86_64 GNU/Linux",
    "uname -s -v -n -r -m": f"Linux #135-Ubuntu SMP {FAKE_HOSTNAME} 5.15.0-125-generic x86_64",
    "nproc": "4",
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uptime": " 09:41:07 up 41 days,  3:12,  1 user,  load average: 0.08, 0.04, 0.01",
    "free -m": (
        "              total        used        free\nMem:           3921         812        1964"
    ),
    "cat /proc/cpuinfo | grep name | wc -l": "4",
    "cat /proc/cpuinfo | grep 'model name' | head -n 1": (
        "model name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz"
    ),
    "cat /etc/issue": "Ubuntu 22.04.5 LTS \\n \\l",
    "pwd": "/root",
    "w": " 09:41:10 up 41 days,  1 user,  load average: 0.08\nUSER TTY FROM LOGIN@ WHAT",
}

WEB_USER_AGENTS_SCANNERS = [
    ("curl/7.88.1", 20),
    ("curl/8.5.0", 10),
    ("python-requests/2.31.0", 14),
    ("python-requests/2.32.3", 8),
    ("Go-http-client/1.1", 14),
    ("Go-http-client/2.0", 4),
    ("zgrab/0.x", 8),
    ("masscan/1.3 (https://github.com/robertdavidgraham/masscan)", 3),
    ("Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", 3),
    ("Wget/1.21.4", 3),
    ("libwww-perl/6.67", 2),
    ("Apache-HttpClient/4.5.13 (Java/11.0.22)", 2),
    ("okhttp/4.12.0", 2),
    # A research crawler: ingest labels these sessions benign and the dashboard hides them (M19).
    ("Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", 5),
]
WEB_USER_AGENTS_BROWSERS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/141.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/139.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Mobile Safari/537.36",
]

# Probe paths: (path, query, weight)
WEB_RECON_PATHS: list[tuple[str, str, int]] = [
    ("/", "", 30),
    ("/robots.txt", "", 6),
    ("/favicon.ico", "", 4),
    ("/.env", "", 14),
    ("/.git/config", "", 8),
    ("/.aws/credentials", "", 3),
    ("/config.json", "", 3),
    ("/server-status", "", 3),
    ("/phpinfo.php", "", 5),
    ("/info.php", "", 4),
    ("/admin/", "", 4),
    ("/login", "", 3),
    ("/cgi-bin/", "", 6),
    ("/actuator/health", "", 2),
    ("/actuator/gateway/routes", "", 2),
    ("/solr/admin/info/system", "wt=json", 2),
    ("/.DS_Store", "", 2),
    ("/backup.zip", "", 2),
    ("/sitemap.xml", "", 2),
    ("/api/v1/pods", "", 1),
]
ENV_SCAN_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.bak",
    "/config/.env",
    "/app/.env",
    "/.git/config",
    "/.git/HEAD",
    "/.aws/credentials",
    "/wp-config.php.bak",
    "/config.php.bak",
    "/.svn/entries",
    "/.htpasswd",
    "/backup.sql",
]
WP_PATHS = [
    "/wp-login.php",
    "/xmlrpc.php",
    "/wp-admin/",
    "/wp-content/plugins/",
    "/wp-json/wp/v2/users",
    "/wp-includes/wlwmanifest.xml",
    "/readme.html",
]
PMA_PATHS = [
    "/phpmyadmin/",
    "/phpMyAdmin/index.php",
    "/pma/",
    "/mysql/",
    "/dbadmin/",
    "/phpmyadmin/setup/index.php",
    "/myadmin/",
]
# (method, path, query, body) well-known benign-looking exploit probes
WEB_EXPLOIT_PROBES: list[tuple[str, str, str, str]] = [
    (
        "GET",
        "/index.php",
        "s=/Index/\\think\\app/invokefunction&function=call_user_func_array"
        "&vars[0]=md5&vars[1][]=probe",
        "",
    ),
    (
        "POST",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        "",
        '<?php echo md5("phpunit");',
    ),
    ("GET", "/cgi-bin/luci/;stok=/locale", "form=country&operation=write&country=$(id)", ""),
    ("GET", "/boaform/admin/formLogin", "username=admin&psd=admin", ""),
    ("POST", "/boaform/admin/formPing", "", "target_addr=;ls&waninf=1_INTERNET_R_VID_154"),
    ("GET", "/cgi-bin/test-cgi", "", ""),
    ("GET", "/setup.cgi", "next_file=netgear.cfg&todo=syscmd&cmd=id", ""),
    ("GET", "/HNAP1/", "", ""),
    ("POST", "/GponForm/diag_Form", "images/", "XWebPageName=diag&diag_action=ping&dest_host=;id"),
    ("GET", "/console/", "", ""),
    ("GET", "/jenkins/script", "", ""),
    ("GET", "/manager/html", "", ""),
]
SHELLSHOCK_UA = '() { :;}; echo; echo "Content-Type: text/plain"; echo probe'

PHP2SHELL_PATHS = [
    "/index.php",
    "/upload.php",
    "/info.php",
    "/test.php",
    "/phpinfo.php",
    "/api.php",
    "/wp-content/uploads/index.php",
    "/admin/index.php",
    "/submit.php",
    "/form.php",
]

WP_USERS = ["admin", "administrator", "editor", "wpadmin", "webmaster"]

MALWARE_PATHS = [
    "/xmrig",
    "/x86_64",
    "/sshd",
    "/kdevtmpfsi",
    "/bins/arm7",
    "/bins/mips",
    "/bins.sh",
    "/a.sh",
    "/setup.sh",
    "/update.sh",
    "/dota.tar.gz",
    "/.x/run",
]
MIRAI_BINS = ["mirai.arm7", "mirai.mips", "mirai.x86", "mirai.mpsl", "mirai.arm", "mirai.ppc"]
TLDS = ["xyz", "top", "site", "click", "online", "icu", "cyou", "buzz", "sbs", "shop"]
SYLLABLES = [
    "ka", "ro", "ne", "vi", "lu", "ta", "mo", "xe", "zu", "bi", "qa", "do", "fi", "ga", "ho",
    "ji", "ky", "no", "pe", "ru", "sa", "te", "ul", "va", "wo", "yu",
]  # fmt: skip
