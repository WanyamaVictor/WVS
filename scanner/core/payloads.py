"""Detection payloads and signatures.

These payloads are intentionally NON-DESTRUCTIVE. They are designed to reveal
whether an input is mishandled (reflected, or triggers a database error) without
modifying, deleting, or exfiltrating data. Do not add destructive payloads
(DROP, DELETE, time-based heavy sleeps, OS command injection, etc.).
"""

from __future__ import annotations

import re

# --- SQL injection probes -------------------------------------------------
# Boolean/quote-breaking probes that commonly surface SQL syntax errors when an
# input is concatenated unsafely into a query.
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1 -- ",
    "') OR ('1'='1",
    "1' AND '1'='2",
]

# Substrings that strongly indicate a database error leaked into the response.
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning:\s*mysqli?",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)",
    r"sqlstate\[",
    r"sqlite_error",
    r"ora-\d{5}",
    r"odbc sql server driver",
    r"supplied argument is not a valid mysql",
    r"mysql_fetch_array\(\)",
]

SQL_ERROR_REGEX = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)


# --- XSS probes -----------------------------------------------------------
# Each probe carries a unique marker so we can confirm exact reflection.
XSS_MARKER = "wvsXSS"

XSS_PAYLOADS = [
    f"<script>alert('{XSS_MARKER}')</script>",
    f"\"><img src=x onerror=alert('{XSS_MARKER}')>",
    f"'><svg/onload=alert('{XSS_MARKER}')>",
    f"{XSS_MARKER}<>\"'",
]


# --- Common sensitive paths for directory / admin discovery ---------------
COMMON_PATHS = [
    "admin", "administrator", "admin/login", "login", "wp-admin",
    "wp-login.php", "user/login", "dashboard", "phpmyadmin", "pma",
    "uploads", "backup", "backups", "config", "config.php", "config.bak",
    ".env", ".git/config", ".git/HEAD", ".htaccess", "robots.txt",
    "server-status", "test.php", "info.php", "phpinfo.php", "db.sql",
    "database.sql", "console", "cpanel",
]

ADMIN_PATHS = [
    "admin", "administrator", "admin/login", "admin/index.php",
    "adminpanel", "admin_area", "controlpanel", "cpanel", "manager",
    "wp-admin", "user/login", "auth/login", "backend",
]
