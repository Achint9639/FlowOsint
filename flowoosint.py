
import sys, os, time, random, threading, queue, re, json, socket
from datetime import datetime
from urllib.parse import urljoin, urlparse

def _check():
    need = []
    for pkg, imp in [
        ("requests",      "requests"),
        ("beautifulsoup4","bs4"),
        ("colorama",      "colorama"),
        ("dnspython",     "dns"),
        ("httpx[http2]",  "httpx"),
        ("lxml",          "lxml"),
        ("selectolax",    "selectolax"),
        ("rich",          "rich"),
        ("tldextract",    "tldextract"),
        ("pydantic",      "pydantic"),
        ("duckdb",        "duckdb"),
        ("trafilatura",   "trafilatura"),
    ]:
        try: __import__(imp)
        except ImportError: need.append(pkg)

    if need:
        print(f"\n  [!] Missing packages: {', '.join(need)}")
        print(f"  Run:  pip install {' '.join(need)}")
        ans = input("\n  Auto-install now? [Y/n]: ").strip().lower()
        if ans in ("","y","yes"):
            import subprocess
            subprocess.check_call([sys.executable,"-m","pip","install"]+need)
            print("\n  [+] Done — restarting...\n"); time.sleep(1)
            os.execv(sys.executable,[sys.executable]+sys.argv)
        sys.exit(0)
_check()

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

import httpx
from bs4 import BeautifulSoup, Comment
from lxml import etree as _lxml_etree
from selectolax.parser import HTMLParser
from colorama import Fore, Style, init
init(autoreset=True)

from rich.console import Console as _RConsole
from rich.table import Table as _RTable
from rich.progress import (Progress as _RProgress, SpinnerColumn,
                            TextColumn, BarColumn, TaskProgressColumn,
                            TimeElapsedColumn)
from rich.panel import Panel as _RPanel
from rich import box as _rbox

_rc = _RConsole()

import tldextract as _tldex

from pydantic import BaseModel, field_validator
from typing import Optional, List

import duckdb as _duckdb

try:
    import trafilatura as _trafilatura
    TRAFILATURA_OK = True
except ImportError:
    TRAFILATURA_OK = False

try:
    import dns.resolver as _dns
    DNS_OK = True
except ImportError:
    DNS_OK = False

PLAYWRIGHT_OK = False
try:
    from playwright.sync_api import sync_playwright as _sync_pw
    PLAYWRIGHT_OK = True
except ImportError:
    pass

R=Fore.RED; BR=Fore.LIGHTRED_EX; Y=Fore.YELLOW; W=Fore.WHITE
G=Fore.GREEN; C=Fore.CYAN; M=Fore.MAGENTA; DIM=Style.DIM
BOLD=Style.BRIGHT; RE=Style.RESET_ALL

class Finding(BaseModel):
    severity:    str
    confidence:  str
    category:    str
    title:       str
    detail:      Optional[str] = ""
    remediation: Optional[str] = ""
    caveats:     Optional[List[str]] = []

    @field_validator("severity")
    @classmethod
    def valid_sev(cls, v):
        allowed = {"CRITICAL","HIGH","MEDIUM","LOW","INFO"}
        v = v.upper()
        if v not in allowed:
            v = "INFO"
        return v

    @field_validator("confidence")
    @classmethod
    def valid_conf(cls, v):
        allowed = {"CONFIRMED","LIKELY","POSSIBLE","UNVERIFIED"}
        v = v.upper()
        if v not in allowed:
            v = "UNVERIFIED"
        return v

    def to_dict(self):
        return self.model_dump()


def tw():
    try: return os.get_terminal_size().columns
    except: return 100

def ctr(text, fill=" "):
    """Centre a raw string (strip ANSI for width calc)."""
    ansi = re.compile(r'\x1b\[[0-9;]*m')
    visible = len(ansi.sub("", text))
    pad = max(0, (tw() - visible) // 2)
    return fill*pad + text

def rule(char="─", color=R):
    return color + char * tw() + RE

def sep(char="▓", color=R):
    print(color + char * tw() + RE)

_log_lock = threading.Lock()

_LOG_FILE: str = ""

def _set_log_file(path: str):
    global _LOG_FILE
    _LOG_FILE = path
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"FlowOsint v2.01 — Live Log\nStarted: {datetime.now()}\n{'='*60}\n\n")

def _write_log(raw: str):
    """Strip ANSI codes and append to live log file."""
    if not _LOG_FILE:
        return
    clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(clean + "\n")
    except Exception:
        pass

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')   

def _log(tag, col, msg):
    ts  = datetime.now().strftime("%H:%M:%S")
    raw = f"[{ts}] [{tag}] {_ANSI_RE.sub('', str(msg))}"
    with _log_lock:
        print(f"{DIM}{W}[{ts}]{RE} {col}{BOLD}[{tag}]{RE} {W}{msg}{RE}")
        _write_log(raw)

def hit(m):    _log("FOUND", BR, m)
def info(m):   _log(" INFO", C,  m)
def warn(m):   _log(" WARN", Y,  m)
def err(m):    _log("ERROR", R,  m)
def sect(m):
    bar = "─" * tw()
    lbl = f"[ {m.upper()} ]"
    with _log_lock:
        print(f"\n{R}{bar}{RE}\n{ctr(f'{BR}{BOLD}{lbl}{RE}')}\n{R}{bar}{RE}\n")
        _write_log(f"\n{bar}\n{lbl}\n{bar}\n")

class Spinner:
    """Wraps rich Progress so we get a proper spinner + elapsed time."""
    def __init__(self, msg="Working"):
        self.msg = msg
        self._prog = _RProgress(
            SpinnerColumn(style="bold red"),
            TextColumn("[bold white]{task.description}"),
            TimeElapsedColumn(),
            transient=True,
            console=_rc,
        )
        self._task = None

    def start(self):
        self._prog.start()
        self._task = self._prog.add_task(f"{self.msg}", total=None)
        return self

    def stop(self, done="Done"):
        self._prog.stop()
        _rc.print(f"  [bold green]✔[/] [white]{done}[/]")


LOGO_LINES = [
    f"{BR}  █████▒  ██▓    ▒█████   █     █░ ▒█████    ██████  ██▓  ███▄    █  ▄▄▄█████▓{RE}",
    f"{R}  ▓██   ▒ ▓██▒  ▒██▒  ██▒▓█░ █ ░█░▒██▒  ██▒▒██    ▒ ▓██▒  ██ ▀█   █  ▓  ██▒ ▓▒{RE}",
    f"{BR}  ▒████ ░ ▒██░  ▒██░  ██▒▒█░ █ ░█ ▒██░  ██▒░ ▓██▄   ▒██▒ ▓██  ▀█ ██▒ ▒ ▓██░ ▒░{RE}",
    f"{R}  ░▓█▒  ░ ▒██░  ▒██   ██░░█░ █ ░█ ▒██   ██░  ▒   ██▒░██░ ▓██▒  ▐▌██▒ ░ ▓██▓ ░ {RE}",
    f"{BR}  ░▒█░   ░██████░ ████▓▒░░░██▒██▓ ░ ████▓▒░▒██████▒▒░██░ ▒██░   ▓██░   ▒██▒ ░ {RE}",
    f"{R}   ▒ ░   ░ ▒░▓  ░ ▒░▒░▒░  ░ ▓░▒ ▒  ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▓   ░ ▒░   ▒ ▒    ▒ ░░  {RE}",
    f"{BR}   ░     ░ ░ ▒  ░ ░ ▒ ▒░    ▒ ░ ░    ░ ▒ ▒░ ░ ░▒  ░ ░ ▒ ░ ░ ░░   ░ ▒░     ░   {RE}",
    f"{R}   ░ ░     ░ ░  ░ ░ ░ ▒     ░   ░  ░ ░ ░ ▒  ░  ░  ░   ▒ ░    ░   ░ ░    ░     {RE}",
    f"{BR}            ░      ░ ░       ░        ░ ░        ░   ░           ░          {RE}",
]

def banner():
    os.system("cls" if os.name=="nt" else "clear")
    for line in LOGO_LINES:
        print(ctr(line))
        time.sleep(0.04)
    print(ctr(f"{DIM}{W}v2.01  ·  Advanced Web Recon & OSINT  ·  github.com/FlowThingy/FlowOsint{RE}"))
    print()


MENU_PAGES = {
    1: {
        "cols": [
            ("Web Recon", [
                ("01","Full Recon (All Modules)"),
                ("02","Dir & File Bruteforce"),
                ("03","Subdomain Probe"),
                ("04","Link & Form Crawler"),
                ("05","JS File Analysis"),
                ("06","HTML Comment Dump"),
                ("07","CSS Asset Extractor"),
            ]),
            ("OSINT", [
                ("08","Robots & Sitemap"),
                ("09","Tech Fingerprint"),
                ("10","WAF / CDN Detect"),
                ("11","Header Inspector"),
                ("12","Cookie Auditor"),
                ("13","DNS Record Lookup"),
                ("14","WHOIS Lookup"),
            ]),
            ("Deep Analysis", [
                ("15","JS Secret Hunter"),
                ("16","Hidden Field Dump"),
                ("17","Form Harvester"),
                ("18","Email Harvester"),
                ("19","Open Redirect Probe"),
                ("20","Open Ports Scan"),
                ("21","Full Report Export"),
            ]),
        ]
    },
    2: {
        "cols": [
            ("Vulnerability", [
                ("22","SQLi Error Probe"),
                ("23","XSS Reflection Test"),
                ("24","LFI Path Test"),
                ("25","SSL/TLS Inspector"),
                ("26","HTTP Methods Test"),
                ("27","Clickjack / CSP Check"),
                ("28","CORS Policy Check"),
            ]),
            ("Network / Intel", [
                ("29","IP Geolocation"),
                ("30","Reverse IP Lookup"),
                ("31","SPF / DMARC Check"),
                ("32","Security Headers"),
                ("33","Google Dork Generator"),
                ("34","Shodan InternetDB"),
                ("35","VirusTotal Domain"),
            ]),
            ("Threat / OSINT APIs", [
                ("36","Wayback Machine"),
                ("37","GreyNoise IP Check"),
                ("38","urlscan.io Analysis"),
                ("40","HaveIBeenPwned"),
                ("41","crt.sh CT Logs"),
                ("42","Email Security Audit"),
                ("43","CMS Context JSON Probe"),
            ]),
        ]
    },
    3: {
        "cols": [
            ("Utilities", [
                ("44","Doc Metadata Harvest"),
                ("45","Risk Score Report"),
                ("46","Playwright JS Scan"),
                ("47","JS-Rendered Crawl"),
                ("48","DuckDB Query"),
                ("49","Trafilatura Extract"),
                ("50","Batch URL Scanner"),
            ]),
            ("Tools", [
                ("51","Hash a String"),
                ("52","Encode / Decode Base64"),
                ("53","Extract All URLs"),
            ]),
            ("", []),
        ]
    },
    4: {
        "cols": [
            ("Social OSINT", [
                ("60","Username Search"),
                ("61","Email OSINT"),
                ("62","GitHub User OSINT"),
            ]),
            ("", []),
            ("System", [
                ("98","Settings"),
                ("00","Exit"),
            ]),
        ]
    },
}

_current_page = [1]

_COMPACT_REMAP = {
    "34": "50",
    "35": "51",
    "36": "52",
    "37": "53",
    "38": "54",
    "40": "55",
    "50": "40",
    "51": "36",
    "52": "37",
    "53": "38",
}

def draw_menu():
    W_term = tw()
    page   = MENU_PAGES[_current_page[0]]
    cols   = page["cols"]
    col_w  = 28
    n      = len(cols)
    total  = n * col_w + (n-1) * 5
    left   = max(0, (W_term - total) // 2)
    pad    = " " * left

    pg    = _current_page[0]
    nav   = f"{R}[{W}I{R}] Info   [{W}S{R}] Settings   [{W}00{R}] Exit"
    nav_r = f"Page {pg}/4  [{W}N{R}] Next ▶{RE}"
    total_nav = len(_ANSI_RE.sub("", nav + nav_r))
    gap = max(1, W_term - total_nav - 2)
    print(f"  {nav}{' '*gap}{nav_r}")

    header_line = pad
    for i,(title,_) in enumerate(cols):
        box = f"{R}┌{'─'*(col_w-2)}┐{RE}"
        header_line += box + ("     " if i < n-1 else "")
    print(header_line)

    title_line = pad
    for i,(title,_) in enumerate(cols):
        inner = f" {BR}{BOLD}{title:<{col_w-4}}{RE} "
        box   = f"{R}│{RE}{inner}{R}│{RE}"
        title_line += box + ("     " if i < n-1 else "")
    print(title_line)

    bottom_line = pad
    for i,_ in enumerate(cols):
        box = f"{R}└{'─'*(col_w-2)}┘{RE}"
        bottom_line += box + ("     " if i < n-1 else "")
    print(bottom_line)

    max_rows = max(len(items) for _,items in cols)
    for r_idx in range(max_rows):
        row_line = pad
        for c_idx,(_,items) in enumerate(cols):
            if r_idx < len(items):
                num, label = items[r_idx]
                cell = f"{R}─{RE} {R}[{W}{num}{R}]{RE} {W}{label:<{col_w-7}}{RE}"
            else:
                cell = " " * col_w
            row_line += cell + ("     " if c_idx < n-1 else "")
        print(row_line)

    print()
    sep()


UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/124.0",
]

def mk_session(proxy=None, cookies=None, extra_headers=None, timeout=12):
    """
    Build an httpx client (HTTP/2 capable) with requests fallback stored.
    Returns an httpx.Client that also has ._fo_timeout and ._requests_session.
    """
    headers = {
        "User-Agent": random.choice(UAS),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if extra_headers:
        headers.update(extra_headers)

    httpx_proxy_kwargs = {"proxy": proxy} if proxy else {}

    try:
        import h2  # noqa: F401
        _http2 = True
    except ImportError:
        _http2 = False

    client = httpx.Client(
        http2=_http2,
        verify=False,
        timeout=timeout,
        headers=headers,
        cookies=cookies or {},
        follow_redirects=True,
        **httpx_proxy_kwargs,
    )
    client._fo_timeout = timeout

    rs = requests.Session()
    rs.verify = False
    rs.headers.update(headers)
    if cookies:
        for k,v in cookies.items(): rs.cookies.set(k,v)
    if proxy: rs.proxies = {"http":proxy,"https":proxy}
    rs._fo_timeout=timeout
    client._requests_session = rs

    return client


def get(session, url):
    """
    Fetch url via httpx (HTTP/2).
    Falls back to requests on httpx failure.
    """
    try:
        r = session.get(url)
        return r
    except Exception:
        pass
    try:
        rs = getattr(session, "_requests_session", None)
        if rs:
            return rs.get(url, timeout=getattr(session,"_fo_timeout",12),
                          verify=False, allow_redirects=True)
    except Exception:
        pass
    return None


def extract_domain(url: str) -> str:
    """
    Return registered domain (e.g. 'example.co.uk' not just 'co.uk').
    tldextract uses the Public Suffix List — handles .co.uk, .github.io etc.
    """
    ext = _tldex.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

def extract_subdomain(url: str) -> str:
    return _tldex.extract(url).subdomain

_DB_PATH = ""
_DB_LOCK = threading.Lock()   # BUG FIX: concurrent DuckDB writes from threaded scans

def _init_db(domain: str):
    """Create/open a per-scan DuckDB file and set up the findings table."""
    global _DB_PATH
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    _DB_PATH = f"flowoosint_{domain.replace('.','_')}_{ts}.duckdb"
    con = _duckdb.connect(_DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY,
            severity    VARCHAR,
            confidence  VARCHAR,
            category    VARCHAR,
            title       VARCHAR,
            detail      VARCHAR,
            remediation VARCHAR,
            caveats     VARCHAR,
            ts          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id       INTEGER PRIMARY KEY,
            type     VARCHAR,
            value    VARCHAR,
            source   VARCHAR,
            ts       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    con.close()
    info(f"Scan DB: {BR}{_DB_PATH}{RE}  (query with duckdb or DBeaver)")

def _db_insert_finding(f: dict):
    if not _DB_PATH: return
    with _DB_LOCK:   # BUG FIX: serialize concurrent inserts from threaded modules
        try:
            con = _duckdb.connect(_DB_PATH)
            con.execute("""
                INSERT INTO findings (severity,confidence,category,title,detail,remediation,caveats)
                VALUES (?,?,?,?,?,?,?)
            """, [f.get("severity"), f.get("confidence"), f.get("category"),
                  f.get("title"), f.get("detail","")[:500],
                  f.get("remediation","")[:500],
                  json.dumps(f.get("caveats",[]))])
            con.close()
        except Exception: pass

def _db_insert_asset(asset_type: str, value: str, source: str = ""):
    if not _DB_PATH: return
    with _DB_LOCK:   # BUG FIX: serialize concurrent inserts from threaded modules
        try:
            con = _duckdb.connect(_DB_PATH)
            con.execute(
                "INSERT INTO assets (type,value,source) VALUES (?,?,?)",
                [asset_type, str(value)[:500], source]
            )
            con.close()
        except Exception: pass

def db_query(sql: str):
    """Run any SQL against the current scan DB and print a rich table."""
    if not _DB_PATH:
        warn("No scan database yet — run a scan first"); return
    try:
        con = _duckdb.connect(_DB_PATH)
        rel = con.execute(sql)
        rows = rel.fetchall()
        cols = [d[0] for d in rel.description]
        con.close()

        t = _RTable(box=_rbox.SIMPLE, style="dim", header_style="bold red")
        for c in cols: t.add_column(c, style="white")
        for row in rows: t.add_row(*[str(v) if v is not None else "" for v in row])
        _rc.print(t)
        info(f"{len(rows)} row(s) returned")
    except Exception as e:
        err(f"DB query error: {e}")


DIRS = [
    "admin","administrator","login","dashboard","panel","cpanel","wp-admin",
    "phpmyadmin","api","api/v1","api/v2","v1","v2","v3","swagger","swagger-ui",
    "docs","doc","backup","backups","bak","db","database","config","conf",
    ".git",".svn",".env","env","secret","secrets","private","uploads","upload",
    "files","media","static","assets","js","css","images","img","vendor","src",
    "app","server","data","dev","staging","test","beta","old","temp","tmp",
    "cache","log","logs","error","debug","trace","help","support","faq","about",
    "profile","user","users","account","accounts","member","register","signup",
    "signin","logout","auth","oauth","token","session","reset","forgot","password",
    "key","keys","cert","ssl","manage","management","settings","setup","install",
    "update","download","export","import","report","search","sitemap","robots",
    "robots.txt","sitemap.xml",".htaccess",".htpasswd","web.config",
    "crossdomain.xml","phpinfo.php","info.php","test.php","debug.php",
    "wp-content","wp-includes","wp-login.php","xmlrpc.php","readme.html",
    "license.txt","composer.json","package.json",".gitignore","Dockerfile",
    "docker-compose.yml","console","terminal","health","healthcheck","status",
    "monitor","metrics","stats","analytics","graphql","websocket","socket",
    "jenkins","gitlab","grafana","kibana","elasticsearch","redis",
    ".well-known","well-known","security.txt",".well-known/security.txt",
    "actuator","actuator/env","actuator/mappings","actuator/health",
    "trace","dump","heapdump","threaddump","beans","autoconfig",
]
EXTS = ["",".php",".html",".htm",".txt",".bak",".zip",".env",
        ".json",".xml",".conf",".log",".sql",".yml",".yaml",".old",".orig"]

def mod_dirbust(base, session, threads=25, wordlist=None):
    sect("Directory & File Discovery")
    # bro if this finds admin panel its over for them fr
    # this function just brute forces paths like /admin /backup /.env etc
    words = wordlist or DIRS
    q = queue.Queue()
    for w in words:
        for e in EXTS:
            q.put(w+e)
    total = q.qsize()
    found_list = []

    with _RProgress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=30, style="red", complete_style="bright_red"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=_rc, transient=True,
    ) as progress:
        task = progress.add_task(f"Probing {total} paths", total=total)

        def worker():
            while True:
                try: path = q.get_nowait()
                except queue.Empty: break
                url = base.rstrip("/")+"/"+path.lstrip("/")
                r   = get(session, url)
                if r and r.status_code not in (404,400,410,406):
                    code, size = r.status_code, len(r.content)
                    clr = BR if code==200 else (Y if code in (301,302,307,308) else C)
                    hit(f"{clr}[{code}]{RE} {W}{url}  {DIM}({size} B)")
                    found_list.append({"url":url,"status":code,"size":size})
                    _db_insert_asset("path", url, f"dirbust:{code}")
                progress.advance(task)
                q.task_done()

        pool = [threading.Thread(target=worker,daemon=True) for _ in range(min(threads,50))]
        for t in pool: t.start()
        for t in pool: t.join()

    info(f"Directory scan done — {BR}{len(found_list)} paths discovered")
    return found_list


SUBS = [
    "www","mail","ftp","smtp","pop","imap","ns1","ns2","dns","vpn","dev",
    "staging","test","beta","api","app","portal","admin","dashboard","git",
    "repo","cdn","static","assets","media","img","upload","blog","shop",
    "store","pay","payment","secure","ssl","login","auth","sso","oauth",
    "id","identity","internal","intranet","corp","hr","crm","erp","support",
    "help","docs","wiki","forum","community","news","webmail","mx","mx1","mx2",
    "email","newsletter","analytics","track","monitor","status","health",
    "metrics","grafana","kibana","jenkins","gitlab","ci","cd","build","deploy",
    "prod","production","qa","uat","sandbox","demo","mobile","m","wap","preview",
    "old","new","legacy","backup","db","database","mysql","pgsql","mongo",
    "redis","elastic","search","img2","images","files","download","uploads",
    "cloud","s3","bucket","storage","video","stream","live","chat","ws",
    "socket","api2","api3","v2","v3","dev2","test2","stg","preprod",
]

def mod_subdomains(domain, session):
    sect("Subdomain Probe")
    # staging.target.com hits different ngl
    reg = extract_domain(domain)
    found_list = []
    q = queue.Queue()
    for s in SUBS: q.put(s+"."+reg)
    total = q.qsize()

    with _RProgress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=30, style="red", complete_style="bright_red"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=_rc, transient=True,
    ) as progress:
        task = progress.add_task(f"Probing {total} subdomains", total=total)

        def probe():
            while True:
                try: host = q.get_nowait()
                except queue.Empty: break
                for scheme in ('https','http'):
                    try:
                        r = get(session, f"{scheme}://{host}")
                        if r and r.status_code not in (400,None):
                            clr = BR if r.status_code==200 else Y
                            hit(f"{clr}[{r.status_code}]{RE} {scheme}://{host}")
                            found_list.append({"host":host,"scheme":scheme,"status":r.status_code})
                            _db_insert_asset("subdomain", host, f"{scheme}:{r.status_code}")
                            break
                    except Exception: continue
                progress.advance(task)
                q.task_done()

        pool = [threading.Thread(target=probe,daemon=True) for _ in range(40)]
        for t in pool: t.start()
        for t in pool: t.join()

    info(f"Subdomain probe done — {BR}{len(found_list)} responded")
    return found_list


def _parse_page_selectolax(html: str, base_url: str, parsed_base):
    """
    Fast extraction using selectolax (Gumbo/Lexbor C parser).
    Returns links, scripts, styles, forms found on this page.
    """
    links, scripts, styles, forms = [], [], [], []
    try:
        tree = HTMLParser(html)
    except Exception:
        return links, scripts, styles, forms

    def _attr(node, key, fallback=""):
        v = node.attributes.get(key, fallback)
        return (v or fallback).strip()

    for node in tree.css("a[href]"):
        href = _attr(node, "href")
        if href:
            full = urljoin(base_url, href)
            links.append(full)

    for node in tree.css("script[src]"):
        src = _attr(node, "src")
        if src:
            scripts.append(urljoin(base_url, src))

    for node in tree.css("link[rel]"):
        rel = _attr(node, "rel")
        if "stylesheet" in rel:
            href = _attr(node, "href")
            if href:
                styles.append(urljoin(base_url, href))

    for form in tree.css("form"):
        action_raw = _attr(form, "action") or base_url
        action = urljoin(base_url, action_raw)
        method = (_attr(form, "method") or "GET").upper()
        fields = [_attr(n, "name")
                  for n in form.css("input,textarea,select")
                  if _attr(n, "name")]
        forms.append({"page":base_url,"action":action,"method":method,"fields":fields})

    return links, scripts, styles, forms


def _parse_page_lxml(html: str, base_url: str):
    """
    Deep extraction using lxml XPath — catches things selectolax misses
    in malformed or complex HTML (data-src lazy-load, noscript blocks, etc.)
    """
    extra = []
    try:
        parser = _lxml_etree.HTMLParser(recover=True)
        tree   = _lxml_etree.fromstring(html.encode("utf-8","replace"), parser)
        if tree is None:
            return extra
        for el in tree.xpath("//*[@data-src]"):
            src = el.get("data-src","").strip()
            if src and not src.startswith("data:"):
                extra.append(urljoin(base_url, src))
        for el in tree.xpath("//noscript//a[@href]"):
            href = el.get("href","").strip()
            if href:
                extra.append(urljoin(base_url, href))
        for tag in ("iframe","embed","object","frame"):
            for el in tree.xpath(f"//{tag}[@src]"):
                src = el.get("src","").strip()
                if src and not src.startswith("data:"):
                    extra.append(urljoin(base_url, src))
        for el in tree.xpath("//meta[@http-equiv]"):
            if "refresh" in el.get("http-equiv","").lower():
                content = el.get("content","")
                m = re.search(r'url=(.+)', content, re.I)
                if m:
                    extra.append(urljoin(base_url, m.group(1).strip().strip("'\"")))
    except Exception:
        pass
    return extra


def _render_with_playwright(url: str, timeout_ms: int = 15000) -> str:
    """
    Launch headless Chromium, navigate to url, wait for network idle,
    return the fully rendered HTML. Only called when PLAYWRIGHT_OK=True.
    """
    if not PLAYWRIGHT_OK:
        return ""
    try:
        with _sync_pw() as pw:
            browser = pw.chromium.launch(headless=True)
            page    = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            html = page.content()
            browser.close()
            return html
    except Exception as e:
        warn(f"Playwright render failed: {e}")
        return ""


def mod_crawler(base, session, depth=2, js_render=False):
    sect("Link, Script & Form Crawler")
    if js_render and PLAYWRIGHT_OK:
        info(f"{G}JS rendering mode ON{RE} (Playwright — full SPA support)")
    elif js_render and not PLAYWRIGHT_OK:
        warn("Playwright not installed — JS rendering disabled. "
             "Install: pip install playwright && playwright install chromium")

    parsed_base = urlparse(base)
    visited, to_visit = set(), {base}
    links,scripts,styles,forms = [],[],[],[]
    lxml_extras = []

    for _ in range(depth):
        nxt = set()
        for url in list(to_visit):
            if url in visited: continue
            visited.add(url)
            r = get(session, url)
            if not r: continue
            ct = r.headers.get("content-type","") if hasattr(r.headers,"get") \
                 else dict(r.headers).get("content-type","")
            if "text/html" not in ct: continue

            html = r.text

            if js_render and PLAYWRIGHT_OK and len(html.strip()) < 3000:
                rendered = _render_with_playwright(url)
                if rendered:
                    html = rendered
                    info(f"{G}[JS-rendered]{RE} {url}")

            pg_links, pg_scripts, pg_styles, pg_forms = \
                _parse_page_selectolax(html, url, parsed_base)

            extras = _parse_page_lxml(html, url)

            for full in pg_links:
                if full not in links:
                    links.append(full)
                    info(f"{C}Link{RE}   {W}{full}")
                p = urlparse(full)
                if p.netloc == parsed_base.netloc and full not in visited:
                    nxt.add(full)

            for src in pg_scripts:
                if src not in scripts:
                    scripts.append(src)
                    hit(f"{Y}Script{RE} {W}{src}")

            for href in pg_styles:
                if href not in styles:
                    styles.append(href)
                    hit(f"{M}Style{RE}  {W}{href}")

            for entry in pg_forms:
                forms.append(entry)
                hit(f"{BR}Form{RE}   {W}{entry['action']}  "
                    f"{DIM}[{entry['method']}] {entry['fields']}")

            for ex in extras:
                if ex not in lxml_extras:
                    lxml_extras.append(ex)
                    info(f"{C}[lxml]{RE} {W}{ex}")

        to_visit = nxt

    info(f"Crawl done — {len(links)} links | {len(scripts)} scripts | "
         f"{len(styles)} styles | {len(forms)} forms | "
         f"{len(lxml_extras)} lxml extras")
    return {"links":links,"scripts":scripts,"styles":styles,
            "forms":forms,"lxml_extras":lxml_extras}



import math as _math

def _shannon_entropy(s: str) -> float:
    """
    Calculate Shannon entropy (bits per character) of a string.
    Real API keys generated by cryptographic RNGs typically score >= 3.5.
    Placeholder / test keys (e.g. 'xxxxxxxx', 'A9A9A9A9', '1234567890') score < 3.0.
    """
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * _math.log2(c / length) for c in freq.values())

def _char_diversity(s: str) -> float:
    """
    Ratio of unique characters to total length.
    A repeating pattern like 'A9A9A9A9' has very low diversity.
    Real keys generally have diversity > 0.4 for strings of length 16+.
    """
    if not s:
        return 0.0
    return len(set(s)) / len(s)

_ENTROPY_SKIP = {
    "Private Key", "Database URL", "Hidden Endpoint",
    "GraphQL", "Relative API", "Internal IP", "Email",
}
_THRESHOLDS = {
    "AWS Access Key":  (3.8, 0.50),
    "AWS Secret":      (4.0, 0.55),
    "Google API Key":  (3.6, 0.50),
    "Stripe Key":      (3.8, 0.50),
    "GitHub Token":    (3.8, 0.50),
    "Slack Token":     (3.5, 0.45),
    "SendGrid Key":    (3.8, 0.50),
    "JWT":             (3.5, 0.40),
    "Bearer Token":    (3.5, 0.40),
    "_default":        (3.2, 0.40),
}

def _is_real_secret(label: str, value: str) -> tuple[bool, float, float]:
    """
    Returns (passes, entropy, diversity).
    Strings that fail either threshold are considered placeholder / fake.
    """
    if label in _ENTROPY_SKIP:
        return True, 0.0, 0.0

    ent = _shannon_entropy(value)
    div = _char_diversity(value)
    min_ent, min_div = _THRESHOLDS.get(label, _THRESHOLDS["_default"])

    passes = (ent >= min_ent) and (div >= min_div)
    return passes, ent, div

_PLACEHOLDER_RE = re.compile(
    r'^(?:'
    r'x{6,}|0{6,}|1{6,}|a{6,}|'           # xxxxxxxx, 000000
    r'(?:test|demo|fake|sample|example|placeholder|your[_\-]?api|changeme|replace|insert)'
    r')',
    re.IGNORECASE
)

JS_PATTERNS = {
    "API Key/Token":   r'(?:api[_\-]?key|apikey|api[_\-]?token|access[_\-]?token)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
    "AWS Access Key":  r'(AKIA[0-9A-Z]{16})',
    "AWS Secret":      r'(?:aws[_\-]?secret|secret[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
    "Google API Key":  r'(AIza[0-9A-Za-z\-_]{35})',
    "Private Key":     r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)',
    "Password":        r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']',
    "Bearer Token":    r'[Bb]earer\s+([A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\.?[A-Za-z0-9\-_.+/=]*)',
    "JWT":             r'(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})',
    "Internal IP":     r'(\b(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b)',
    "Email":           r'([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
    "Hidden Endpoint": r'(?:fetch|axios\.(?:get|post|put|delete)|http\.get)\s*\(\s*["\']([/][^"\']{3,})["\']',
    "GraphQL":         r'(?:graphql|gql)["\s:=(]+([/][^"\')\s]{3,})',
    "Database URL":    r'((?:mongodb|mysql|postgres|redis|mssql)://[^\s"\'<>]+)',
    "S3 Bucket":       r's3\.amazonaws\.com/([a-z0-9\-\.]{3,})',
    "Secret Key":      r'(?:secret[_\-]?key|secretkey)\s*[=:]\s*["\']([^"\']{8,})["\']',
    "Relative API":    r'(["\'](?:\/api\/|\/rest\/|\/v\d\/)[a-zA-Z0-9/_\-?=&]{4,}["\'])',
    "Slack Token":     r'(xox[baprs]-[0-9A-Za-z\-]{10,})',
    "Stripe Key":      r'((?:sk|pk)_(?:live|test)_[0-9A-Za-z]{24,})',
    "GitHub Token":    r'(gh[pousr]_[A-Za-z0-9]{36,})',
    "Twilio SID":      r'(AC[a-z0-9]{32})',
    "SendGrid Key":    r'(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})',
}

def mod_js(scripts, session):
    sect("JavaScript Intelligence — Secrets & Endpoints")
    # devs really just leave aws keys in prod js files 💀
    result  = []
    rejected = 0

    for url in scripts:
        resp = get(session, url)
        if not resp:
            continue
        found_here = False

        for label, pat in JS_PATTERNS.items():
            for m in re.findall(pat, resp.text, re.IGNORECASE):
                val = m if isinstance(m, str) else (m[0] if m else "")
                val = val.strip().strip('"\'')
                if not val:
                    continue

                if _PLACEHOLDER_RE.match(val):
                    info(f"{DIM}[placeholder] {label}: {val[:60]}")
                    rejected += 1
                    continue

                passes, ent, div = _is_real_secret(label, val)
                if not passes:
                    info(
                        f"{DIM}[low-entropy] {label}: {val[:60]}"
                        f"  entropy={ent:.2f}  diversity={div:.2f}"
                    )
                    rejected += 1
                    continue

                ent_tag = f"{DIM}[H:{ent:.2f} D:{div:.2f}]{RE}" if ent > 0 else ""
                hit(
                    f"{BR}{label}{RE}: {W}{val[:120]}{RE}"
                    f"  {ent_tag}  {DIM}← {url}"
                )
                result.append({
                    "script":    url,
                    "type":      label,
                    "value":     val[:120],
                    "entropy":   round(ent, 3),
                    "diversity": round(div, 3),
                })
                found_here = True

        if not found_here:
            info(f"Clean: {DIM}{url}")

    info(
        f"JS scan done — {BR}{len(result)} real findings{RE}  "
        f"{DIM}({rejected} low-entropy / placeholder strings discarded)"
    )
    return result


def mod_html(base, session):
    sect("HTML Intelligence — Hidden Fields, Comments & Meta")
    r = get(session, base)
    if not r: err("Could not fetch page"); return {}
    html = r.text
    out  = {"hidden":[],"comments":[],"meta":[],"iframes":[],"inline":[]}

    try:
        tree = HTMLParser(html)

        for node in tree.css("input[type=hidden]"):
            name = node.attributes.get("name","")
            val  = node.attributes.get("value","")
            if name:
                hit(f"{BR}Hidden Input{RE}: {W}{name}{RE} = {DIM}{val[:80]}")
                out["hidden"].append({"name":name,"value":val})

        for node in tree.css("meta"):
            n = node.attributes.get("name","") or node.attributes.get("property","")
            v = node.attributes.get("content","")
            if n and v:
                info(f"{C}Meta{RE}: {W}{n}{RE} = {DIM}{v[:120]}")
                out["meta"].append({"name":n,"content":v})

        for node in tree.css("iframe"):
            src = node.attributes.get("src","")
            if src:
                hit(f"{M}iFrame{RE}: {W}{src}")
                out["iframes"].append(src)

    except Exception as e:
        warn(f"selectolax error: {e}")

    try:
        parser = _lxml_etree.HTMLParser(recover=True)
        tree_l = _lxml_etree.fromstring(html.encode("utf-8","replace"), parser)
        if tree_l is not None:
            for el in tree_l.xpath("//input[@name and not(@type='hidden')]"):
                n = el.get("name","")
                v = el.get("value","")
                if n and any(kw in n.lower() for kw in
                             ["token","csrf","key","secret","id","hash","api"]):
                    hit(f"{Y}Interesting Input{RE}: {W}{n}{RE} = {DIM}{v[:80]}")
                    out["hidden"].append({"name":n,"value":v,"note":'non-hidden but sensitive name'})
            for el in tree_l.xpath("//*[@data-user or @data-token or @data-key or @data-id]"):
                for attr in ("data-user","data-token","data-key","data-id",
                             "data-api","data-secret","data-email"):
                    v = el.get(attr)
                    if v:
                        hit(f"{BR}data-attr{RE}: {W}{attr}{RE} = {DIM}{v[:80]}")
                        out["hidden"].append({"name":attr,"value":v,"note":"data attribute"})
    except Exception as e:
        warn(f"lxml pass error: {e}")

    try:
        soup = BeautifulSoup(html, "lxml")
        for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
            c = c.strip()
            if len(c) > 3:
                hit(f"{Y}<!-- -->{RE}: {DIM}{c[:200]}")
                out["comments"].append(c[:200])
    except Exception:
        try:
            soup = BeautifulSoup(html, "html.parser")
            for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
                c = c.strip()
                if len(c) > 3:
                    out["comments"].append(c[:200])
        except Exception: pass

    inline_pats = {
        "API Path":   r'["\'](?:\/api\/|\/rest\/|\/v\d\/)[^"\'<>\s]{4,}["\']',
        "Credential": r'(?:key|token|secret|password)\s*[=:]\s*["\']([^"\']{6,})["\']',
        "Email":      r'([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})',
        "JWT":        r'(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})',
    }
    try:
        tree_s = HTMLParser(html)
        for node in tree_s.css("script"):
            content = node.text() or ""
            if not content: continue
            for label, pat in inline_pats.items():
                for m in re.findall(pat, content, re.IGNORECASE):
                    val = (m if isinstance(m,str) else m).strip().strip('"\'')
                    if not val or _PLACEHOLDER_RE.match(val): continue
                    passes, ent, div = _is_real_secret(label, val)
                    if not passes: continue
                    hit(f"{BR}Inline {label}{RE}: {W}{val[:120]}")
                    out["inline"].append({"type":label,"value":val[:120],
                                          "entropy":round(ent,3),"diversity":round(div,3)})
    except Exception as e: pass

    info("HTML analysis complete")
    return out


def mod_css(styles, session):
    sect("CSS Asset Extractor")
    results = []
    up  = re.compile(r'url\(["\']?([^"\')\s]+)["\']?\)', re.I)
    imp = re.compile(r'@import\s+["\']([^"\']+)["\']', re.I)
    for css_url in styles:
        r = get(session, css_url)
        if not r: continue
        for u in set(up.findall(r.text)+imp.findall(r.text)):
            if u.startswith("data:"): continue
            full = urljoin(css_url, u)
            hit("%s%s%s: %s%s" % (M, "CSS Asset", RE, W, full))
            results.append(full)
    info(f"CSS scan done — {len(results)} assets")
    return results


def mod_robots(base, session):
    sect("Robots.txt & Sitemap Intelligence")
    paths_found = []
    targets = ["robots.txt","sitemap.xml","sitemap_index.xml",
               ".well-known/security.txt",".well-known/openid-configuration",
               "crossdomain.xml","clientaccesspolicy.xml","sitemap.gz"]
    for p in targets:
        url = base.rstrip("/")+"/"+p
        r   = get(session, url)
        if r and r.status_code == 200:
            hit(f"{BR}[200]{RE} {W}{url}")
            for line in r.text.splitlines()[:80]:
                line = line.strip()
                if line: info(f"  {DIM}{line}")
                if re.match(r'(?i)(disallow|allow|sitemap|<loc>)',line):
                    val = re.sub(r'(?i)(disallow:|allow:|sitemap:|</?loc>)','',line).strip()
                    if val and val != "/":
                        paths_found.append({"src":p,"path":urljoin(base,val)})
        else:
            warn(f"Not found: {url}")
    info(f"Done — {len(paths_found)} paths disclosed")
    return paths_found



_WAP_SIGS = {
    "WordPress":         {"body":["wp-content","wp-includes","wp-json"],"header":{"x-powered-by":"wordpress"}},
    "Joomla":            {"body":["joomla","option=com_","/administrator/"]},
    "Drupal":            {"body":["drupal","/sites/default/files"],"header":{"x-generator":"drupal"}},
    "Magento":           {"body":["magento","mage/","Mage.Cookies"]},
    "Shopify":           {"body":["cdn.shopify.com","Shopify.theme"]},
    "WooCommerce":       {"body":["woocommerce","wc-","WooCommerce"]},
    "Ghost":             {"body":["ghost-url","content/themes/"]},
    "Wix":               {"body":["wix.com","_wix_"]},
    "Squarespace":       {"body":["squarespace","sqsp."]},
    "Webflow":           {"body":["webflow.com","data-wf-"]},
    "Laravel":           {"body":["laravel_session","laravel"],"cookie":"laravel_session"},
    "Django":            {"body":["csrfmiddlewaretoken","django"],"cookie":"csrftoken"},
    "Ruby on Rails":     {"header":{"x-runtime":""},"body":["rails"]},
    "ASP.NET":           {"body":["__viewstate","asp.net"],"header":{"x-aspnet-version":""}},
    "ASP.NET MVC":       {"header":{"x-aspnetmvc-version":""}},
    "Spring Boot":       {"body":["Whitelabel Error Page","Spring"]},
    "Express.js":        {"header":{"x-powered-by":"express"}},
    "Next.js":           {"body":["_next/static","__NEXT_DATA__"]},
    "Nuxt.js":           {"body":["__nuxt","_nuxt/"]},
    "Gatsby":            {"body":["gatsby-","___gatsby"]},
    "React":             {"body":["react","__react","data-reactroot"]},
    "Vue.js":            {"body":["vue.js","__vue__","v-bind:","v-on:"]},
    "Angular":           {"body":["ng-version","angular.js","ng-app"]},
    "Svelte":            {"body":["svelte","__svelte"]},
    "jQuery":            {"body":["jquery.min.js","jquery.js"]},
    "Bootstrap":         {"body":["bootstrap.min.css","bootstrap.bundle"]},
    "Tailwind CSS":      {"body":["tailwind","tw-"]},
    "Apache":            {"header":{"server":"apache"}},
    "Nginx":             {"header":{"server":"nginx"}},
    "IIS":               {"header":{"server":"microsoft-iis"}},
    "Caddy":             {"header":{"server":"caddy"}},
    "LiteSpeed":         {"header":{"server":"litespeed"}},
    "OpenResty":         {"header":{"server":"openresty"}},
    "PHP":               {"header":{"x-powered-by":"php"},"body":[".php"]},
    "Python":            {"header":{"x-powered-by":"python"}},
    "Java":              {"header":{"x-powered-by":"servlet"}},
    "Node.js":           {"header":{"x-powered-by":"node"}},
    "Cloudflare":        {"header":{"cf-ray":"","server":"cloudflare"},"body":["__cfduid","cf-ray"]},
    "AWS CloudFront":    {"header":{"x-amz-cf-id":"","via":"cloudfront"}},
    "Fastly":            {"header":{"x-fastly-request-id":"","x-served-by":"cache-"}},
    "Akamai":            {"header":{"x-akamai-transformed":"","x-check-cacheable":""}},
    "Varnish":           {"header":{"x-varnish":"","via":"varnish"}},
    "Sucuri":            {"header":{"x-sucuri-id":""}},
    "Google Analytics":  {"body":["google-analytics.com/analytics.js","gtag("]},
    "Google Tag Manager":{"body":["googletagmanager.com/gtm.js"]},
    "Hotjar":            {"body":["hotjar.com","hjSetting"]},
    "Mixpanel":          {"body":["mixpanel.com","mixpanel.init"]},
    "Segment":           {"body":["cdn.segment.com","analytics.js"]},
    "GraphQL":           {"body":["graphql","__schema","IntrospectionQuery"]},
    "Elasticsearch":     {"body":["elasticsearch","_search","_index"]},
    "Firebase":          {"body":["firebaseapp.com","initializeApp","firebase"]},
    "Stripe":            {"body":["js.stripe.com","Stripe("]},
    "PayPal":            {"body":["paypalobjects.com","paypal.Buttons"]},
    "phpMyAdmin":        {"body":["phpMyAdmin","pma_"]},
    "Swagger UI":        {"body":["swagger-ui","SwaggerUIBundle"]},
    "Jenkins":           {"body":["hudson.plugins","jenkins"]},
    "Grafana":           {"body":["grafana","grafana-app"]},
}

def mod_fingerprint(base, session):
    sect("Technology Fingerprinting (Wappalyzer signatures)")
    r = get(session, base)
    if not r: err("Unreachable"); return {}

    hdrs  = {k.lower():v.lower() for k,v in dict(r.headers).items()}
    body  = r.text.lower()
    tech  = {}

    detected = []
    for name, sigs in _WAP_SIGS.items():
        matched = False
        for hk, hv in sigs.get("header",{}).items():
            hdr_val = hdrs.get(hk,"")
            if hdr_val and (not hv or hv in hdr_val):
                matched = True; break
        if not matched:
            for pat in sigs.get("body",[]):
                if pat.lower() in body:
                    matched = True; break
        if not matched and "cookie" in sigs:
            for c in r.cookies if hasattr(r,"cookies") else []:
                if sigs["cookie"] in (c.name if hasattr(c,"name") else str(c)).lower():
                    matched = True; break
        if matched:
            detected.append(name)
            tech[name] = True

    if detected:
        t = _RTable(title="Detected Technologies", box=_rbox.SIMPLE,
                    style="dim", header_style="bold red", title_style="bold bright_red")
        t.add_column("Technology", style="bold white")
        t.add_column("Category", style="yellow")
        cats = {
            "WordPress":"CMS","Joomla":"CMS","Drupal":"CMS","Magento":"CMS",
            "Shopify":"CMS","WooCommerce":"CMS","Ghost":"CMS","Wix":"CMS",
            "Squarespace":"CMS","Webflow":"CMS","Laravel":"Framework",
            "Django":"Framework","Ruby on Rails":"Framework","ASP.NET":"Framework",
            "ASP.NET MVC":"Framework","Spring Boot":"Framework","Express.js":"Framework",
            "Next.js":"Framework","Nuxt.js":"Framework","Gatsby":"Framework",
            "React":"JS Library","Vue.js":"JS Library","Angular":"JS Library",
            "Svelte":"JS Library","jQuery":"JS Library","Bootstrap":"CSS Framework",
            "Tailwind CSS":"CSS Framework","Apache":"Server","Nginx":"Server",
            "IIS":"Server","Caddy":"Server","LiteSpeed":"Server","OpenResty":"Server",
            "PHP":"Language","Python":"Language","Java":"Language","Node.js":"Language",
            "Cloudflare":"CDN/Security","AWS CloudFront":"CDN","Fastly":"CDN",
            "Akamai":"CDN","Varnish":"Cache","Sucuri":"Security",
            "Google Analytics":"Analytics","Google Tag Manager":"Analytics",
            "Hotjar":"Analytics","Mixpanel":"Analytics","Segment":"Analytics",
            "GraphQL":"API","Elasticsearch":"Search","Firebase":"Backend",
            "Stripe":"Payments","PayPal":"Payments","phpMyAdmin":"Admin",
            "Swagger UI":"API Docs","Jenkins":"CI/CD","Grafana":"Monitoring",
        }
        for name in detected:
            t.add_row(name, cats.get(name,"Other"))
        _rc.print(t)

    interesting = ["server","x-powered-by","x-generator","x-aspnet-version",
                   "x-runtime","x-backend-server","x-served-by","via",
                   "cf-ray","x-amz-cf-id","x-varnish"]
    for h in interesting:
        v = hdrs.get(h)
        if v:
            hit(f"{Y}{h}{RE}: {W}{v}")
            tech[h] = v

    if TRAFILATURA_OK:
        try:
            text = _trafilatura.extract(r.text, include_comments=True,
                                         include_tables=True) or ""
            ver_matches = re.findall(r'(?:version|v)\s*[:\s]*([\d]+\.[\d]+[\.\d]*)',
                                     text, re.I)
            for v in set(ver_matches[:10]):
                info(f"{C}Version string{RE}: {W}{v}")
                tech[f"version_{v}"] = v
            path_matches = re.findall(r'(?:/home/|/var/|/usr/|C:\\)[^\s<>"\']{5,40}', text)
            for p in set(path_matches[:5]):
                hit(f"{BR}Internal path in content{RE}: {W}{p}")
                tech[f"internal_path"] = p
        except Exception:
            pass

    info(f"Fingerprint done — {BR}{len(detected)} technologies detected")
    return tech


def mod_waf(base, session):
    sect("WAF / CDN Detection")
    # cloudflare detected = skill issue for us not gonna lie
    r = get(session, base)
    if not r: err("Unreachable"); return []
    h   = {k.lower():v.lower() for k,v in r.headers.items()}
    body= r.text.lower()
    waf_sigs = {
        "Cloudflare":       ["cf-ray","__cfduid","cloudflare"],
        "AWS WAF":          ["x-amzn-requestid","awselb","x-amz-cf-id"],
        "Akamai":           ["akamai","x-akamai-transformed","x-check-cacheable"],
        "Incapsula":        ["x-iinfo","incap_ses","visid_incap"],
        "Sucuri":           ["x-sucuri-id","sucuri"],
        "ModSecurity":      ["mod_security","modsecurity"],
        "F5 BIG-IP":        ["bigipserver","f5-bigip"],
        "Imperva":          ["imperva"],
        "Fastly":           ["x-fastly","fastly-debug"],
        "Varnish":          ["x-varnish"],
        "Barracuda":        ["barracuda_"],
        "Reblaze":          ["rbzid","reblaze"],
        "Wallarm":          ["wallarm"],
    }
    detected = []
    for name, sigs in waf_sigs.items():
        if any(s in h or any(s in v for v in h.values()) or s in body
               for s in sigs):
            hit(f"{BR}WAF/CDN{RE}: {W}{name}")
            detected.append(name)
    if not detected:
        info("No known WAF/CDN signatures detected")
    return detected


def mod_dns(domain):
    sect("DNS Record Lookup")
    results = {}
    if not DNS_OK:
        warn("dnspython not installed — skipping DNS")
        return results
    record_types = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA","SRV"]
    for rtype in record_types:
        try:
            answers = _dns.resolve(domain, rtype, lifetime=5)
            for rdata in answers:
                hit(f"{Y}{rtype:6}{RE}: {W}{rdata.to_text()}")
                results.setdefault(rtype,[]).append(rdata.to_text())
        except Exception as e:
            pass
    if not results:
        warn("No DNS records found or domain unreachable")
    return results


def mod_whois(domain):
    sect("WHOIS Lookup")
    try:
        import subprocess
        out = subprocess.check_output(
            ["whois", domain], stderr=subprocess.DEVNULL,
            timeout=15, text=True
        )
        keep = ["domain","registrar","creation","expir","updated","name server",
                "status","email","country","org","registrant"]
        for line in out.splitlines():
            ll = line.lower()
            if any(k in ll for k in keep) and ":" in line:
                parts = line.split(":",1)
                hit(f"{Y}{parts[0].strip():25}{RE}: {W}{parts[1].strip()}")
        return {"raw": out[:2000]}
    except FileNotFoundError:
        warn("whois binary not found — try: apt install whois")
    except Exception as e:
        warn(f"WHOIS failed: {e}")
    return {}


def mod_ssl(domain):
    sect("SSL / TLS Certificate Inspector")
    # expired cert = instant report on bugcrowd lol
    import ssl, socket as sk
    try:
        ctx = ssl.create_default_context()
        with sk.create_connection((domain,443),timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as conn:
                cert = conn.getpeercert()
                cipher = conn.cipher()

        tmp = "%s  %s  %s-bit" % (cipher[0], cipher[1], cipher[2])
        hit(f"{Y}Cipher{RE}: {W}{tmp}")

        subject = dict(x[0] for x in cert.get("subject",()))
        issuer  = dict(x[0] for x in cert.get("issuer",()))
        hit(f"{Y}Subject{RE}: {W}{subject.get('commonName','?')}")
        hit(f"{Y}Issuer{RE}:  {W}{issuer.get('organizationName','?')}")
        hit(f"{Y}Valid from{RE}: {W}{cert.get('notBefore','?')}")
        hit(f"{Y}Valid to{RE}:   {W}{cert.get('notAfter','?')}")

        sans = [v for t,v in cert.get("subjectAltName",[]) if t=="DNS"]
        for s in sans:
            info(f"  SAN: {W}{s}")
        return {"subject":subject,"issuer":issuer,"sans":sans,"cipher":cipher}
    except ssl.SSLError as e:
        err(f"SSL error: {e}")
    except Exception as e:
        err(f"SSL inspect failed: {e}")
    return {}


def mod_sec_headers(base, session):
    sect("Security Headers Audit")
    r = get(session, base)
    if not r: err("Unreachable"); return {}
    h = {k.lower():v for k,v in r.headers.items()}
    checks = {
        "Strict-Transport-Security": "HSTS prevents downgrade attacks",
        "Content-Security-Policy":   "CSP limits script/resource origins",
        "X-Frame-Options":           "Prevents clickjacking",
        "X-Content-Type-Options":    "Prevents MIME sniffing",
        "Referrer-Policy":           "Controls referrer leakage",
        "Permissions-Policy":        "Restricts browser features",
        "X-XSS-Protection":          "Legacy XSS filter (deprecated but notable)",
        "Cross-Origin-Opener-Policy":"Isolates browsing context",
        "Cross-Origin-Resource-Policy":"Controls cross-origin reads",
    }
    results = {}
    for hdr, desc in checks.items():
        val = h.get(hdr.lower())
        if val:
            hit(f"{G}[PRESENT]{RE} {Y}{hdr}{RE}: {W}{val}")
        else:
            warn(f"{R}[MISSING]{RE} {Y}{hdr}{RE}  {DIM}({desc})")
        results[hdr] = val or "MISSING"
    return results


def mod_cors(base, session):
    sect("CORS Policy Check")
    try:
        r = session.options(base,
                            headers={"Origin":"https://evil-attacker.com",
                                     "Access-Control-Request-Method":"GET"})
    except Exception:
        try:
            rs = getattr(session,"_requests_session",None)
            if not rs: err("No session"); return {}
            r = rs.options(base, timeout=rs._fo_timeout, verify=False,
                           headers={"Origin":"https://evil-attacker.com"})
        except Exception as e:
            err(str(e)); return {}

    acao = r.headers.get("access-control-allow-origin","") or \
           r.headers.get("Access-Control-Allow-Origin","")
    acac = r.headers.get("access-control-allow-credentials","") or \
           r.headers.get("Access-Control-Allow-Credentials","")
    acam = r.headers.get("access-control-allow-methods","") or \
           r.headers.get("Access-Control-Allow-Methods","")

    if acao == "*":
        hit(f"{BR}CORS WILDCARD{RE}: Any origin can read responses")
    elif "evil-attacker.com" in acao:
        hit(f"{BR}CORS REFLECTS ORIGIN{RE}: Server mirrors supplied Origin — misconfigured")
    elif acao:
        hit(f"{Y}CORS Allow-Origin{RE}: {W}{acao}")
    else:
        info("No CORS headers returned")

    if acac.lower() == "true":
        hit(f"{BR}Allow-Credentials: true{RE}")
    if acam:
        info(f"Allowed Methods: {W}{acam}")

    return {"origin":acao,"credentials":acac,"methods":acam}


def mod_methods(base, session):
    sect("HTTP Methods Test")
    methods = ["GET","POST","PUT","DELETE","PATCH","OPTIONS","HEAD","TRACE","CONNECT"]
    results = {}
    rs = getattr(session, "_requests_session", None)
    for m in methods:
        try:
            if rs:
                r = rs.request(m, base, timeout=rs._fo_timeout, allow_redirects=False)
            else:
                r = session.request(m, base)
            clr = BR if r.status_code < 300 else (Y if r.status_code < 400 else DIM+W)
            hit(f"{clr}{m:<8}{RE} → {r.status_code}")
            results[m] = r.status_code
        except Exception:
            results[m] = "error"
    if results.get("TRACE") not in ("error", 405, 501):
        warn("TRACE method may be enabled — potential XST risk")
    return results


def mod_open_redirect(base, session):
    sect("Open Redirect Probe")
    payloads = [
        "//evil.com","//evil.com/","https://evil.com",
        "/\\evil.com","/%2F%2Fevil.com",
    ]
    params = ["redirect","url","next","return","returnTo","redir",
              "destination","goto","target","continue","r","u","link"]
    found_list = []
    for param in params:
        for payload in payloads:
            test_url = f"{base}?{param}={payload}"
            r = get(session, test_url)
            if r:
                loc = r.headers.get("Location","")
                if "evil.com" in loc or r.url.startswith("http://evil.com"):
                    hit(f"{BR}Open Redirect{RE}: {W}{test_url}  →  {loc}")
                    found_list.append({"url":test_url,"location":loc})
    if not found_list:
        info("No obvious open redirects detected")
    return found_list


def mod_sqli(base, session):
    sect("SQLi Error Probe (passive)")
    # if this pops a mysql error the dev is cooked 💀
    payloads = ["'","\"","' OR '1'='1","' OR 1=1--","\" OR \"1\"=\"1"]
    db_errors = [
        r"sql syntax","mysql_fetch",r"ORA-\d{5}","Microsoft OLE DB",
        r"SQLSTATE\[",r"pg_query\(","sqlite3_","Unclosed quotation",
        "syntax error","database error","ODBC SQL","DB2 SQL",
    ]
    found_list = []
    params = ["id","q","search","s","query","page","cat","item","product"]
    for param in params:
        for payload in payloads:
            url = f"{base}?{param}={requests.utils.quote(payload)}"
            r   = get(session, url)
            if not r: continue
            for pat in db_errors:
                if re.search(pat, r.text, re.I):
                    hit(f"{BR}SQLi Error{RE}: param={W}{param}{RE} payload={W}{payload}{RE}")
                    hit(f"  Pattern matched: {DIM}{pat}")
                    found_list.append({"param":param,"payload":payload})
                    break
    if not found_list:
        info("No SQLi error patterns detected (not conclusive)")
    return found_list


def mod_emails(links, session):
    sect("Email Harvester")
    # people really just put their emails on every page lmaooo
    emails  = set()
    ep      = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    targets = links[:80]
    total   = len(targets)
    _lock   = threading.Lock()

    q = queue.Queue()
    for url in targets:
        q.put(url)

    with _RProgress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=30, style="red", complete_style="bright_red"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=_rc, transient=True,
    ) as progress:
        task = progress.add_task(f"Harvesting emails from {total} pages", total=total)

        def worker():
            while True:
                try:
                    url = q.get_nowait()
                except queue.Empty:
                    break
                try:
                    rs = getattr(session, "_requests_session", None)
                    if rs:
                        r = rs.get(url, timeout=6, verify=False, allow_redirects=True)
                    else:
                        r = session.get(url)
                    if r:
                        found = ep.findall(r.text)
                        with _lock:
                            for e in found:
                                if e not in emails:
                                    emails.add(e)
                                    hit(f"{Y}Email{RE}: {W}{e}")
                except Exception:
                    pass
                progress.advance(task)
                q.task_done()

        pool = [threading.Thread(target=worker, daemon=True) for _ in range(15)]
        for t in pool: t.start()
        for t in pool: t.join()

    info(f"Email harvest done — {BR}{len(emails)} address(es) found")
    return list(emails)


def mod_ports(domain):
    sect("Open Ports Scanner (top 25)")
    # mongodb on port 27017 with no auth is so cooked
    top_ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,
                 993,995,1723,3306,3389,5900,8080,8443,8888,27017,6379,5432]
    try:
        ip = socket.gethostbyname(domain)
        info(f"Resolved {domain} → {W}{ip}")
    except Exception:
        err(f"Cannot resolve {domain}"); return []

    open_ports = []
    q = queue.Queue()
    for p in top_ports: q.put(p)

    def scan():
        while True:
            try: port = q.get_nowait()
            except queue.Empty: break
            try:
                with socket.create_connection((ip, port), timeout=1):
                    hit(f"{BR}OPEN{RE}  {W}{domain}:{port}")
                    open_ports.append(port)
            except Exception:
                pass
            q.task_done()

    pool = [threading.Thread(target=scan,daemon=True) for _ in range(25)]
    for t in pool: t.start()
    for t in pool: t.join()
    if not open_ports:
        open_ports = []
    info(f"Port scan done — {len(open_ports)} open ports")
    return open_ports


def mod_dorks(domain):
    sect("Google Dork Generator")
    dorks = [
        f'site:{domain}',
        f'site:{domain} filetype:pdf',
        f'site:{domain} filetype:xls OR filetype:xlsx',
        f'site:{domain} filetype:doc OR filetype:docx',
        f'site:{domain} filetype:sql',
        f'site:{domain} filetype:log',
        f'site:{domain} filetype:env',
        f'site:{domain} inurl:admin',
        f'site:{domain} inurl:login',
        f'site:{domain} inurl:config',
        f'site:{domain} inurl:backup',
        f'site:{domain} inurl:api',
        f'site:{domain} intitle:"index of"',
        f'site:{domain} intitle:"phpinfo()"',
        f'site:{domain} intext:"sql syntax"',
        f'site:{domain} intext:"Warning: mysql"',
        f'site:{domain} intext:"powered by" inurl:readme',
        f'site:{domain} "DB_PASSWORD" OR "DB_USER"',
        f'site:{domain} ext:bak OR ext:old OR ext:orig',
        f'cache:{domain}',
    ]
    print()
    for d in dorks:
        hit(f"{Y}dork{RE}: {W}{d}")
        info(f"  → https://www.google.com/search?q={requests.utils.quote(d)}")
    info(f"Generated {len(dorks)} dorks for {domain}")
    return dorks


def mod_geoip(domain, session):
    sect("IP Geolocation")
    try:
        ip = socket.gethostbyname(domain)
        info(f"Resolved: {W}{domain}{RE} → {BR}{ip}")
    except Exception:
        err(f"Cannot resolve {domain}"); return {}

    r2 = get(session, f"https://ipapi.co/{ip}/json/")
    if not r2:
        r2 = get(session, f"http://ip-api.com/json/{ip}")
    if not r2: err("GeoIP lookup failed"); return {}
    try:
        data = r2.json()
        fields = ["ip","city","region","country_name","org","timezone","latitude","longitude"]
        for f in fields:
            v = data.get(f) or data.get(f.replace("_name",""))
            if v: hit(f"{Y}{f:15}{RE}: {W}{v}")
        return data
    except Exception as e:
        err(str(e)); return {}


def mod_spf_dmarc(domain):
    sect("SPF / DMARC / DKIM Check")
    if not DNS_OK:
        warn("dnspython not available — skipping")
        return {}
    results = {}
    checks = {
        "SPF":   domain,
        "DMARC": f"_dmarc.{domain}",
        "DKIM":  f"default._domainkey.{domain}",
    }
    for label, qdom in checks.items():
        try:
            ans = _dns.resolve(qdom,"TXT",lifetime=5)
            for rd in ans:
                val = rd.to_text().strip('"')
                hit(f"{Y}{label}{RE}: {W}{val[:120]}")
                results[label] = val
        except Exception:
            warn(f"{label}: not found for {qdom}")
    return results


def mod_lfi(base, session):
    sect("LFI Path Probe (passive)")
    payloads = [
        "../etc/passwd","../../etc/passwd","../../../etc/passwd",
        "....//....//etc/passwd","%2e%2e%2fetc%2fpasswd",
        "../windows/win.ini","../../windows/win.ini",
    ]
    params = ["file","page","include","path","dir","document","pg","view","load"]
    found_list = []
    indicators = ["root:x:","bin:x:","[extensions]","for 16-bit app"]
    for param in params:
        for payload in payloads:
            url = f"{base}?{param}={payload}"
            r   = get(session, url)
            if not r: continue
            if any(ind in r.text for ind in indicators):
                hit(f"{BR}LFI Likely{RE}: {W}{url}")
                found_list.append(url)
                break
    if not found_list:
        info("No LFI indicators found (not conclusive)")
    return found_list


def mod_xss(base, session):
    sect("XSS Reflection Test (passive)")
    marker   = "F1owXSSprobe8472"
    params   = ["q","s","search","query","id","name","input","text","p","msg","term"]
    payloads = [
        f"<{marker}>",f'"{marker}"',f"'{marker}'",
        f"<script>{marker}</script>",
    ]
    found_list = []
    for param in params:
        for payload in payloads:
            url = f"{base}?{param}={requests.utils.quote(payload)}"
            r   = get(session, url)
            if not r: continue
            if marker in r.text:
                ctype = r.headers.get("Content-Type","")
                if "text/html" in ctype:
                    hit(f"{BR}XSS Reflected{RE}: param={W}{param}{RE} payload={W}{payload}")
                    found_list.append({"param":param,"payload":payload})
                    break
    if not found_list:
        info("No reflections detected (manual testing still recommended)")
    return found_list


def mod_crtsh(domain, session):
    sect("Certificate Transparency — crt.sh Subdomain Discovery")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    info(f"Querying crt.sh for *.{domain} ...")
    r = get(session, url)
    if not r:
        err("crt.sh unreachable"); return []
    try:
        data = r.json()
    except Exception:
        err("crt.sh returned invalid JSON"); return []

    seen = set()
    found_list = []
    for entry in data:
        names = entry.get("name_value","").splitlines()
        for name in names:
            name = name.strip().lstrip("*.")
            if name and domain in name and name not in seen:
                seen.add(name)
                issued   = entry.get("not_before","?")[:10]
                issuer   = entry.get("issuer_ca_id","?")
                hit(f"{BR}{name:<50}{RE}  {DIM}issued={issued}  ca={issuer}")
                found_list.append({"subdomain": name, "issued": issued})

    info(f"crt.sh done — {len(found_list)} unique subdomains discovered")
    return found_list


_DKIM_SELECTORS = [
    "default","google","mail","s1","s2","k1","k2","dkim",
    "smtp","email","selector1","selector2","mimecast",
    "mailjet","sendgrid","pm","mx","dkimkey",
]

_RISK_DB = {
    "spf_missing":  ("HIGH",   "SPF record missing",
                     "Anyone can send email as @{domain}. Add a TXT record: v=spf1 include:... -all"),
    "spf_plus_all": ("HIGH",   "SPF uses +all — completely open relay",
                     "Change +all to -all to block unauthorised senders"),
    "spf_tilde_all":("MEDIUM", "SPF uses ~all (SoftFail) — not enforced",
                     "Upgrade ~all to -all for strict enforcement"),
    "dmarc_missing":("HIGH",   "DMARC record missing",
                     "Add: _dmarc.{domain} TXT v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"),
    "dmarc_none":   ("MEDIUM", "DMARC policy is p=none — no enforcement",
                     "Change p=none to p=quarantine or p=reject"),
    "dmarc_quarantine":("LOW", "DMARC policy is p=quarantine — partial protection",
                     "Upgrade to p=reject for full protection"),
    "dkim_missing": ("MEDIUM", "No DKIM selectors found",
                     "Configure DKIM signing on your mail server and publish the public key in DNS"),
}

def _risk(key, domain, findings):
    sev, title, fix = _RISK_DB[key]
    clr = BR if sev=="HIGH" else (Y if sev=="MEDIUM" else C)
    hit(f"{clr}[{sev}]{RE} {W}{title.replace('{domain}',domain)}")
    info(f"  Remediation: {DIM}{fix.replace('{domain}',domain)}")
    findings.append({"severity":sev, "title":title.replace("{domain}",domain),
                     "remediation":fix.replace("{domain}",domain)})

def mod_email_security(domain):
    sect("DNS & Email Security Audit — SPF / DMARC / DKIM")
    if not DNS_OK:
        warn("dnspython not available — install it: pip install dnspython"); return {}

    results  = {"spf":None,"dmarc":None,"dkim":[],"findings":[]}
    findings = results["findings"]

    try:
        ans = _dns.resolve(domain, "TXT", lifetime=6)
        spf = None
        for rd in ans:
            txt = rd.to_text().strip('"')
            if txt.startswith("v=spf1"):
                spf = txt
                hit(f"{Y}SPF{RE}: {W}{txt}")
                break
        if not spf:
            _risk("spf_missing", domain, findings)
        elif "+all" in spf:
            _risk("spf_plus_all", domain, findings)
        elif "~all" in spf:
            _risk("spf_tilde_all", domain, findings)
        else:
            hit(f"{G}SPF OK{RE}: strict -all enforcement detected")
        results["spf"] = spf
    except Exception:
        _risk("spf_missing", domain, findings)

    try:
        ans = _dns.resolve(f"_dmarc.{domain}", "TXT", lifetime=6)
        dmarc = None
        for rd in ans:
            txt = rd.to_text().strip('"')
            if "v=DMARC1" in txt:
                dmarc = txt
                hit(f"{Y}DMARC{RE}: {W}{txt}")
                break
        if not dmarc:
            _risk("dmarc_missing", domain, findings)
        elif "p=none" in dmarc:
            _risk("dmarc_none", domain, findings)
        elif "p=quarantine" in dmarc:
            _risk("dmarc_quarantine", domain, findings)
        else:
            hit(f"{G}DMARC OK{RE}: p=reject enforced")
        results["dmarc"] = dmarc
    except Exception:
        _risk("dmarc_missing", domain, findings)

    dkim_found = []
    for sel in _DKIM_SELECTORS:
        try:
            qname = f"{sel}._domainkey.{domain}"
            ans   = _dns.resolve(qname, "TXT", lifetime=3)
            for rd in ans:
                txt = rd.to_text().strip('"')
                if "p=" in txt:
                    hit(f"{G}DKIM selector '{sel}'{RE}: {W}{txt[:80]}")
                    dkim_found.append({"selector":sel,"record":txt[:200]})
        except Exception:
            pass
    if not dkim_found:
        _risk("dkim_missing", domain, findings)
    results["dkim"] = dkim_found

    info(f"Email security audit done — {len(findings)} findings")
    return results


def mod_cms_context(base, session):
    sect("CMS Context JSON Probe")
    probes = [
        "?format=json",
        "?format=page-context",
        "?format=json-pretty",
        "/api/2/site/config",
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts?per_page=5",
        "/wp-json",
        "/?rest_route=/wp/v2/users",
        "/feed/json",
        "/manifest.json",
        "/config.json",
        "/settings.json",
        "/api/settings",
        "/api/config",
        "/api/me",
        "/api/user",
        "/.well-known/assetlinks.json",
        "/apple-app-site-association",
    ]
    results = []
    for probe in probes:
        url = base.rstrip("/") + probe
        r   = get(session, url)
        if not r or r.status_code != 200:
            continue
        ct = r.headers.get("Content-Type","")
        if "json" not in ct and not r.text.strip().startswith("{"):
            continue
        try:
            data = r.json()
        except Exception:
            continue

        hit(f"{BR}CMS JSON exposed{RE}: {W}{url}")

        def _walk(obj, path=""):
            if isinstance(obj, dict):
                for k,v in obj.items():
                    _walk(v, f"{path}.{k}" if path else k)
            elif isinstance(obj, list):
                for i,v in enumerate(obj[:5]):
                    _walk(v, f"{path}[{i}]")
            else:
                sval = str(obj)[:120]
                interesting = ["id","user","author","email","name","login",
                               "username","password","token","key","secret",
                               "collection","draft","timestamp","version",
                               "path","url","internal","admin","role"]
                if any(kw in path.lower() for kw in interesting):
                    hit(f"  {Y}{path}{RE}: {W}{sval}")
                    results.append({"url":url,"key":path,"value":sval})

        _walk(data)
        if not results:
            info(f"  JSON returned but no sensitive keys found at {DIM}{url}")

    info(f"CMS context probe done — {len(results)} sensitive keys exposed")
    return results


def mod_doc_metadata(links, session):
    sect("Document & Asset Metadata Harvester")
    doc_exts  = (".pdf",".docx",".doc",".xlsx",".xls",".pptx",".ppt",".odt")
    doc_links = [l for l in links if any(l.lower().endswith(e) for e in doc_exts)]

    if not doc_links:
        info("No document links found in crawled pages"); return []

    info(f"Found {len(doc_links)} document(s) — extracting metadata")
    results = []

    for url in doc_links[:20]:          # cap at 20 to stay reasonable
        r = get(session, url)
        if not r or r.status_code != 200:
            continue

        hit(f"{BR}Document{RE}: {W}{url}  {DIM}({len(r.content)//1024} KB)")
        meta = {"url": url, "fields": {}}

        if url.lower().endswith(".pdf"):
            try:
                raw = r.content
                for tag in [b"/Author", b"/Creator", b"/Producer",
                            b"/Title",  b"/Subject", b"/Keywords",
                            b"/CreationDate", b"/ModDate"]:
                    idx = raw.find(tag)
                    if idx == -1: continue
                    chunk = raw[idx:idx+200].decode("latin-1", errors="ignore")
                    m = re.search(r'[(/]([^/()<>\r\n]{2,})[)/]', chunk)
                    if m:
                        val = m.group(1).strip()
                        key = tag.decode().strip("/")
                        hit(f"  {Y}{key:<18}{RE}: {W}{val}")
                        meta["fields"][key] = val
            except Exception as e:
                warn(f"PDF parse error: {e}")

        elif any(url.lower().endswith(e) for e in (".docx",".xlsx",".pptx")):
            try:
                import zipfile, io
                z = zipfile.ZipFile(io.BytesIO(r.content))
                core = None
                for name in z.namelist():
                    if "core.xml" in name or "app.xml" in name:
                        core = z.read(name).decode("utf-8", errors="ignore")
                        break
                if core:
                    tag_map = {
                        "dc:creator":"Author", "cp:lastModifiedBy":"LastModifiedBy",
                        "dcterms:created":"Created", "dcterms:modified":"Modified",
                        "cp:revision":"Revision", "dc:title":"Title",
                        "dc:description":"Description", "cp:keywords":"Keywords",
                        "AppVersion":"AppVersion", "Application":"Application",
                        "Company":"Company",
                    }
                    for xml_tag, label in tag_map.items():
                        m = re.search(rf'<{xml_tag}[^>]*>([^<]+)<', core)
                        if m:
                            val = m.group(1).strip()
                            hit(f"  {Y}{label:<18}{RE}: {W}{val}")
                            meta["fields"][label] = val
            except Exception as e:
                warn(f"Office parse error: {e}")

        if meta["fields"]:
            results.append(meta)

    info(f"Document harvest done — {len(results)} documents with metadata")
    return results





SOCIAL_PLATFORMS = [
    {"name": "GitHub",        "url": "https://github.com/{}",                     "ok": 200, "not_found": 404},
    {"name": "Twitter/X",     "url": "https://twitter.com/{}",                    "ok": 200, "not_found": 404},
    {"name": "Instagram",     "url": "https://www.instagram.com/{}/",             "ok": 200, "not_found": 404},
    {"name": "Reddit",        "url": "https://www.reddit.com/user/{}",            "ok": 200, "not_found": 404},
    {"name": "TikTok",        "url": "https://www.tiktok.com/@{}",               "ok": 200, "not_found": 404},
    {"name": "LinkedIn",      "url": "https://www.linkedin.com/in/{}",           "ok": 200, "not_found": 404},
    {"name": "YouTube",       "url": "https://www.youtube.com/@{}",              "ok": 200, "not_found": 404},
    {"name": "Twitch",        "url": "https://www.twitch.tv/{}",                 "ok": 200, "not_found": 404},
    {"name": "Pinterest",     "url": "https://www.pinterest.com/{}/",            "ok": 200, "not_found": 404},
    {"name": "Telegram",      "url": "https://t.me/{}",                          "ok": 200, "not_found": 404},
    {"name": "Steam",         "url": "https://steamcommunity.com/id/{}",         "ok": 200, "not_found": 404},
    {"name": "Pastebin",      "url": "https://pastebin.com/u/{}",                "ok": 200, "not_found": 404},
    {"name": "HackerOne",     "url": "https://hackerone.com/{}",                 "ok": 200, "not_found": 404},
    {"name": "Bugcrowd",      "url": "https://bugcrowd.com/{}",                  "ok": 200, "not_found": 404},
    {"name": "Dev.to",        "url": "https://dev.to/{}",                        "ok": 200, "not_found": 404},
    {"name": "Medium",        "url": "https://medium.com/@{}",                   "ok": 200, "not_found": 404},
    {"name": "Hashnode",      "url": "https://hashnode.com/@{}",                 "ok": 200, "not_found": 404},
    {"name": "GitLab",        "url": "https://gitlab.com/{}",                    "ok": 200, "not_found": 404},
    {"name": "Bitbucket",     "url": "https://bitbucket.org/{}",                 "ok": 200, "not_found": 404},
    {"name": "Keybase",       "url": "https://keybase.io/{}",                    "ok": 200, "not_found": 404},
    {"name": "Gravatar",      "url": "https://en.gravatar.com/{}",               "ok": 200, "not_found": 404},
    {"name": "Fiverr",        "url": "https://www.fiverr.com/{}",                "ok": 200, "not_found": 404},
    {"name": "Replit",        "url": "https://replit.com/@{}",                   "ok": 200, "not_found": 404},
    {"name": "HuggingFace",   "url": "https://huggingface.co/{}",                "ok": 200, "not_found": 404},
    {"name": "DockerHub",     "url": "https://hub.docker.com/u/{}",              "ok": 200, "not_found": 404},
    {"name": "npm",           "url": "https://www.npmjs.com/~{}",                "ok": 200, "not_found": 404},
    {"name": "PyPI",          "url": "https://pypi.org/user/{}",                 "ok": 200, "not_found": 404},
    {"name": "Codecademy",    "url": "https://www.codecademy.com/profiles/{}",   "ok": 200, "not_found": 404},
    {"name": "Tryhackme",     "url": "https://tryhackme.com/p/{}",               "ok": 200, "not_found": 404},
    {"name": "HackTheBox",    "url": "https://app.hackthebox.com/users/{}",      "ok": 200, "not_found": 404},
]

def _social_check_one(platform: dict, username: str, rs) -> dict | None:
    url = platform["url"].format(username)
    try:
        r = rs.get(url, timeout=8, verify=False, allow_redirects=True)
        if r.status_code == platform["ok"]:
            not_found_clues = [
                "page not found", "user not found", "doesn't exist",
                "no user found", "404", "this account", "not available",
            ]
            body = r.text.lower()
            if any(c in body for c in not_found_clues):
                return None
            return {"platform": platform["name"], "url": url, "status": r.status_code}
    except Exception:
        pass
    return None


def mod_username_search(username: str, session):
    sect(f"Username Search — {username}")
    # put username here not your own obv lol
    # checks like 30 platforms at once to see if the username exists
    rs      = getattr(session, "_requests_session", None)
    if not rs:
        err("No requests session available"); return []

    found   = []
    total   = len(SOCIAL_PLATFORMS)
    _lock   = threading.Lock()
    q       = queue.Queue()
    for p in SOCIAL_PLATFORMS:
        q.put(p)

    with _RProgress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=30, style="red", complete_style="bright_red"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=_rc, transient=True,
    ) as progress:
        task = progress.add_task(
            f"Checking {total} platforms for '{username}'", total=total)

        def worker():
            while True:
                try:
                    platform = q.get_nowait()
                except queue.Empty:
                    break
                result = _social_check_one(platform, username, rs)
                if result:
                    with _lock:
                        found.append(result)
                        hit(f"{G}[FOUND]{RE} {BR}{result['platform']:<20}{RE} {W}{result['url']}")
                        _db_insert_asset("social_profile", result["url"],
                                         f"username:{username}")
                progress.advance(task)
                q.task_done()

        pool = [threading.Thread(target=worker, daemon=True) for _ in range(20)]
        for t in pool: t.start()
        for t in pool: t.join()

    if not found:
        info(f"Username '{username}' not found on any checked platform")
    else:
        info(f"Found on {BR}{len(found)}{RE} platform(s):")
        t = _RTable(box=_rbox.SIMPLE, style="dim", header_style="bold red")
        t.add_column("Platform", style="bold white", width=20)
        t.add_column("URL", style="cyan")
        for r in found:
            t.add_row(r["platform"], r["url"])
        _rc.print(t)

    return found


def mod_email_osint(email: str, session):
    sect(f"Email OSINT — {email}")
    # if hibp returns breaches its already too late for them
    rs = getattr(session, "_requests_session", None)
    if not rs:
        err("No requests session available"); return {}

    results = {"email": email, "breaches": [], "accounts": [], "formats": []}

    local, _, domain = email.partition("@")

    info(f"Target: {W}{email}{RE}  local={BR}{local}{RE}  domain={BR}{domain}")

    info(f"Checking HaveIBeenPwned for {W}{email}")
    try:
        r = rs.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{requests.utils.quote(email)}",
            headers={"User-Agent": "FlowOsint/2.01"},
            timeout=8, verify=False
        )
        if r.status_code == 200:
            breaches = r.json()
            for b in breaches:
                name = b.get("Name","?")
                date = b.get("BreachDate","?")
                hit(f"{BR}[BREACH]{RE} {W}{name}{RE}  {DIM}{date}")
                results["breaches"].append({"name": name, "date": date})
            info(f"Found in {BR}{len(breaches)}{RE} breach(es)")
        elif r.status_code == 404:
            hit(f"{G}Not found in any known breaches")
        else:
            warn(f"HIBP returned {r.status_code}")
    except Exception as e:
        warn(f"HIBP check failed: {e}")

    info(f"Probing Gravatar for {W}{email}")
    try:
        import hashlib
        md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
        r = rs.get(
            f"https://www.gravatar.com/{md5}.json",
            timeout=6, verify=False
        )
        if r.status_code == 200:
            data = r.json()
            entry = data.get("entry", [{}])[0]
            display = entry.get("displayName","")
            username = entry.get("preferredUsername","")
            profile = f"https://www.gravatar.com/{md5}"
            hit(f"{G}[GRAVATAR]{RE} {W}{display or username}{RE} → {C}{profile}")
            results["accounts"].append({"platform": "Gravatar", "url": profile,
                                        "name": display or username})
        else:
            info("No Gravatar profile found")
    except Exception as e:
        warn(f"Gravatar check failed: {e}")

    info(f"Generating common email format variations for {W}{domain}")
    parts = local.replace(".", " ").replace("_", " ").replace("-", " ").split()
    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        formats = [
            f"{first}.{last}@{domain}",
            f"{first}{last}@{domain}",
            f"{last}.{first}@{domain}",
            f"{first[0]}{last}@{domain}",
            f"{first}.{last[0]}@{domain}",
            f"{first[0]}.{last}@{domain}",
        ]
        for fmt in formats:
            if fmt != email:
                info(f"  {DIM}{fmt}")
                results["formats"].append(fmt)

    info(f"Email OSINT done — {len(results['breaches'])} breach(es)  "
         f"{len(results['accounts'])} account(s) found")
    return results


def mod_github_user(username: str, session):
    sect(f"GitHub User OSINT — {username}")
    # devs exposing their work email in commits is wild every time
    # grabs profile repos and mines commit history for leaked emails
    rs = getattr(session, "_requests_session", None)
    if not rs:
        err("No requests session available"); return {}

    results = {"profile": {}, "repos": [], "emails": [], "sensitive_repos": []}

    info(f"Fetching profile for {W}{username}")
    try:
        r = rs.get(f"https://api.github.com/users/{username}",
                   headers={"Accept": "application/vnd.github+json"},
                   timeout=10, verify=False)
        if r.status_code == 404:
            err(f"GitHub user '{username}' not found"); return {}
        if r.status_code != 200:
            warn(f"GitHub API returned {r.status_code}"); return {}

        p = r.json()
        results["profile"] = p

        fields = [
            ("Name",        p.get("name","")),
            ("Bio",         p.get("bio","")),
            ("Company",     p.get("company","")),
            ("Location",    p.get("location","")),
            ("Email",       p.get("email","")),
            ("Blog",        p.get("blog","")),
            ("Twitter",     p.get("twitter_username","")),
            ("Followers",   str(p.get("followers",""))),
            ("Following",   str(p.get("following",""))),
            ("Public repos",str(p.get("public_repos",""))),
            ("Created",     p.get("created_at","")[:10]),
            ("Profile",     p.get("html_url","")),
        ]
        for label, val in fields:
            if val:
                hit(f"{Y}{label:<14}{RE}: {W}{val}")

        if p.get("email"):
            results["emails"].append({"source": "profile", "email": p["email"]})

    except Exception as e:
        err(f"GitHub profile fetch failed: {e}"); return {}

    info(f"Fetching repositories for {W}{username}")
    try:
        r = rs.get(
            f"https://api.github.com/users/{username}/repos?per_page=100&sort=updated",
            headers={"Accept": "application/vnd.github+json"},
            timeout=10, verify=False
        )
        if r.status_code == 200:
            repos = r.json()
            results["repos"] = repos

            sensitive_names = [
                "dotfiles","config","secrets","private","credentials",
                "backup","keys","passwords","token","api","env","hidden"
            ]

            t = _RTable(box=_rbox.SIMPLE, style="dim", header_style="bold red")
            t.add_column("Repository", style="bold white", width=35)
            t.add_column("Stars", style="yellow", width=6)
            t.add_column("Language", style="cyan", width=14)
            t.add_column("Updated", style="dim white", width=12)

            for repo in repos[:20]:
                name     = repo.get("name","")
                stars    = str(repo.get("stargazers_count",0))
                lang     = repo.get("language","") or ""
                updated  = (repo.get("updated_at","") or "")[:10]
                is_fork  = repo.get("fork", False)
                t.add_row(
                    f"{'[fork] ' if is_fork else ''}{name}",
                    stars, lang, updated
                )
                for kw in sensitive_names:
                    if kw in name.lower():
                        hit(f"{BR}Sensitive repo name{RE}: {W}{repo.get('html_url','')}")
                        results["sensitive_repos"].append(repo.get("html_url",""))
                        break

            _rc.print(t)
            info(f"Total public repos: {BR}{len(repos)}")

    except Exception as e:
        warn(f"Repo fetch failed: {e}")

    info(f"Mining commit history for email addresses")
    try:
        r = rs.get(
            f"https://api.github.com/users/{username}/events/public?per_page=100",
            headers={"Accept": "application/vnd.github+json"},
            timeout=10, verify=False
        )
        if r.status_code == 200:
            events = r.json()
            seen_emails = set()
            ep = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
            for event in events:
                if event.get("type") != "PushEvent": continue
                for commit in event.get("payload",{}).get("commits",[]):
                    author = commit.get("author",{})
                    email  = author.get("email","")
                    name   = author.get("name","")
                    if email and email not in seen_emails:
                        if "noreply" not in email:
                            seen_emails.add(email)
                            hit(f"{G}[COMMIT EMAIL]{RE} {W}{email}{RE}  {DIM}({name})")
                            results["emails"].append({"source": "commit", "email": email, "name": name})
            if not seen_emails:
                info("No email addresses found in public commit history")
    except Exception as e:
        warn(f"Event mining failed: {e}")

    info(f"GitHub OSINT done — {len(results['repos'])} repos  "
         f"{len(results['emails'])} email(s)  "
         f"{len(results['sensitive_repos'])} sensitive repo(s)")
    return results


def mod_shodan(domain, session):
    """
    Shodan InternetDB — free, no API key required.
    Returns open ports, CVEs, tags, and hostnames for the resolved IP.
    Source: https://internetdb.shodan.io
    """
    sect("Shodan InternetDB Lookup")
    # free shodan hits different no cap
    try:
        ip = socket.gethostbyname(domain)
        info(f"Resolved {domain} → {W}{ip}")
    except Exception:
        err(f"Cannot resolve {domain}"); return {}

    r = get(session, f"https://internetdb.shodan.io/{ip}")
    if not r or r.status_code != 200:
        warn(f"Shodan InternetDB returned no data for {ip}"); return {}

    try:
        data = r.json()
    except Exception:
        err("Shodan InternetDB: invalid JSON response"); return {}

    ports = data.get("ports", [])
    cpes  = data.get("cpes", [])
    vulns = data.get("vulns", [])
    tags  = data.get("tags", [])
    hosts = data.get("hostnames", [])

    if ports:
        hit(f"{Y}Open Ports{RE}: {W}{', '.join(str(p) for p in ports)}")
        for p in ports:
            _db_insert_asset("shodan_port", str(p), f"shodan:{ip}")
    if hosts:
        hit(f"{Y}Hostnames{RE}: {W}{', '.join(hosts)}")
    if tags:
        hit(f"{Y}Tags{RE}: {W}{', '.join(tags)}")
    if cpes:
        for c in cpes:
            hit(f"{C}CPE{RE}: {W}{c}")
    if vulns:
        for v in vulns:
            hit(f"{BR}CVE{RE}: {W}{v}")
            _db_insert_asset("cve", v, f"shodan:{ip}")
    if not ports and not vulns:
        info(f"No data found — {ip} not indexed by Shodan InternetDB")

    info(f"Shodan done — {len(ports)} ports  {len(vulns)} CVEs  {len(cpes)} CPEs")
    return data


def mod_virustotal(domain, session):
    """
    VirusTotal public domain report — no API key, uses the public web API endpoint.
    Returns detection ratio, categories, and last analysis stats.
    Source: https://www.virustotal.com
    """
    sect("VirusTotal Domain Report")
    import base64 as _b64

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    r = get(session, f"https://www.virustotal.com/ui/domains/{domain}")
    if not r or r.status_code != 200:
        warn(f"VirusTotal: no data for {domain} (status {r.status_code if r else 'N/A'})")
        info("Tip: Set a free VT API key via Settings > extra_headers for full results")
        return {}

    try:
        data = r.json()
    except Exception:
        err("VirusTotal: invalid JSON"); return {}

    attrs = (data.get("data") or {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    cats  = attrs.get("categories", {})
    rep   = attrs.get("reputation", "?")

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)
    total_eng  = sum(stats.values()) if stats else 0

    clr = BR if malicious > 0 else (Y if suspicious > 0 else G)
    if total_eng:
        hit(f"{clr}Detections{RE}: {W}{malicious} malicious  {suspicious} suspicious  "
            f"{harmless} harmless  (of {total_eng} engines)")
    hit(f"{Y}Reputation score{RE}: {W}{rep}")

    if cats:
        for vendor, cat in list(cats.items())[:8]:
            info(f"  {DIM}{vendor}{RE}: {W}{cat}")

    creation = attrs.get("creation_date")
    if creation:
        info(f"{C}Created{RE}: {W}{datetime.fromtimestamp(creation).strftime('%Y-%m-%d')}")

    _db_insert_asset("virustotal", domain,
                     f"malicious={malicious} suspicious={suspicious}")

    info(f"VirusTotal done — {malicious} malicious flags across {total_eng} engines")
    return {"stats": stats, "reputation": rep, "categories": cats}


def mod_wayback(domain, session):
    """
    Wayback Machine (Internet Archive) — availability check + recent snapshots.
    Source: https://archive.org / https://timetravel.mementoweb.org
    """
    sect("Wayback Machine — Archive Lookup")
    results = {"available": False, "snapshots": [], "oldest": None, "newest": None}

    avail_url = f"https://archive.org/wayback/available?url={domain}"
    r = get(session, avail_url)
    if r and r.status_code == 200:
        try:
            d = r.json()
            snap = d.get("archived_snapshots", {}).get("closest", {})
            if snap.get("available"):
                results["available"] = True
                ts  = snap.get("timestamp","?")
                url = snap.get("url","?")
                hit(f"{G}Archived{RE}: {W}{url}")
                hit(f"{Y}Closest snapshot{RE}: {W}{ts[:4]}-{ts[4:6]}-{ts[6:8]}")
                results["snapshots"].append({"timestamp": ts, "url": url})
            else:
                warn(f"No Wayback snapshot found for {domain}")
        except Exception:
            pass

    cdx_url = (f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json"
               f"&fl=timestamp,statuscode,mimetype&limit=5&from=&to=&collapse=timestamp:6")
    r2 = get(session, cdx_url)
    if r2 and r2.status_code == 200:
        try:
            rows = r2.json()
            if rows and len(rows) > 1:  # first row is header
                for row in rows[1:]:
                    ts, sc, mt = row[0], row[1], row[2]
                    info(f"  {DIM}{ts[:4]}-{ts[4:6]}-{ts[6:8]}{RE}  "
                         f"[{sc}]  {mt}")
                    results["snapshots"].append({"timestamp": ts, "status": sc})
                results["oldest"] = rows[1][0]
                results["newest"] = rows[-1][0]
                oldest = results["oldest"]
                newest = results["newest"]
                hit(f"{Y}Oldest snapshot{RE}: {W}{oldest[:4]}-{oldest[4:6]}-{oldest[6:8]}")
                hit(f"{Y}Newest snapshot{RE}: {W}{newest[:4]}-{newest[4:6]}-{newest[6:8]}")
        except Exception:
            pass

    info(f"Full history: {C}https://web.archive.org/web/*/{domain}{RE}")
    info(f"Wayback done — {len(results['snapshots'])} snapshots retrieved")
    return results


def mod_greynoise(domain, session):
    """
    GreyNoise Community API — free, no key needed for basic lookups.
    Checks whether the resolved IP is known internet background noise,
    a malicious actor, or benign.
    Source: https://viz.greynoise.io / https://api.greynoise.io
    """
    sect("GreyNoise IP Intelligence")
    try:
        ip = socket.gethostbyname(domain)
        info(f"Resolved {domain} → {W}{ip}")
    except Exception:
        err(f"Cannot resolve {domain}"); return {}

    r = get(session, f"https://api.greynoise.io/v3/community/{ip}")
    if not r:
        warn("GreyNoise API unreachable"); return {}

    if r.status_code == 404:
        info(f"{G}GreyNoise{RE}: {ip} has NOT been seen scanning the internet — clean")
        return {"seen": False, "ip": ip}

    if r.status_code != 200:
        warn(f"GreyNoise returned HTTP {r.status_code}"); return {}

    try:
        data = r.json()
    except Exception:
        err("GreyNoise: invalid JSON"); return {}

    noise     = data.get("noise", False)
    riot      = data.get("riot", False)
    classif   = data.get("classification", "unknown")
    name      = data.get("name", "")
    link      = data.get("link", "")
    message   = data.get("message", "")

    if riot:
        hit(f"{G}RIOT{RE}: {ip} is a known benign service ({W}{name}{RE})")
    elif noise and classif == "malicious":
        hit(f"{BR}MALICIOUS{RE}: {ip} is flagged as malicious internet scanner")
    elif noise:
        hit(f"{Y}NOISE{RE}: {ip} is internet background noise ({W}{classif}{RE})")
    else:
        info(f"GreyNoise: {ip} — {message or 'not in dataset'}")

    if name:   hit(f"{Y}Name{RE}: {W}{name}")
    if link:   info(f"Details: {C}{link}{RE}")

    _db_insert_asset("greynoise", ip,
                     f"noise={noise} riot={riot} classification={classif}")

    info(f"GreyNoise done — noise={noise}  riot={riot}  classification={classif}")
    return data


def mod_urlscan(target, session):
    """
    urlscan.io — submit a URL for analysis and retrieve the result.
    Uses the public submission endpoint (no API key for basic scans).
    Source: https://urlscan.io
    """
    sect("urlscan.io — URL Analysis")
    submit_url = "https://urlscan.io/api/v1/scan/"
    headers    = {"Content-Type": "application/json"}
    payload    = json.dumps({"url": target, "visibility": "public"})

    rs = getattr(session, "_requests_session", None)
    if not rs:
        warn("urlscan: no requests session available"); return {}

    try:
        resp = rs.post(submit_url, data=payload, headers=headers,
                       timeout=rs._fo_timeout, verify=False)
    except Exception as e:
        err(f"urlscan submit failed: {e}"); return {}

    if resp.status_code not in (200, 201):
        warn(f"urlscan: submit returned HTTP {resp.status_code}")
        if resp.status_code == 400:
            warn("urlscan: URL may be malformed or already recently scanned")
        return {}

    try:
        sub = resp.json()
    except Exception:
        err("urlscan: invalid JSON on submit"); return {}

    scan_id  = sub.get("uuid", "")
    result_u = sub.get("result", "")
    api_url  = sub.get("api", "")
    hit(f"{G}Submitted{RE}: scan ID = {W}{scan_id}")
    info(f"Result URL: {C}{result_u}{RE}")
    info(f"Waiting 20s for scan to complete...")

    time.sleep(20)

    r2 = get(session, api_url) if api_url else None
    if not r2 or r2.status_code != 200:
        warn(f"urlscan result not ready yet — check manually: {result_u}")
        return {"scan_id": scan_id, "result_url": result_u}

    try:
        data = r2.json()
    except Exception:
        err("urlscan: invalid result JSON"); return {"scan_id": scan_id}

    page  = data.get("page", {})
    meta  = data.get("meta", {})
    stats = data.get("stats", {})
    lists = data.get("lists", {})

    hit(f"{Y}IP{RE}: {W}{page.get('ip','?')}")
    hit(f"{Y}Country{RE}: {W}{page.get('country','?')}")
    hit(f"{Y}Server{RE}: {W}{page.get('server','?')}")
    hit(f"{Y}ASN{RE}: {W}{page.get('asnname','?')}")

    if page.get("tlsIssuer"):
        info(f"{C}TLS Issuer{RE}: {W}{page['tlsIssuer']}")
    if page.get("redirected"):
        hit(f"{Y}Redirect{RE}: {W}{page['redirected']}")

    req_count = stats.get("requests", 0)
    dom_count = len(lists.get("domains", []))
    info(f"Requests: {W}{req_count}{RE}  Domains contacted: {W}{dom_count}")

    for dom in lists.get("domains", [])[:10]:
        info(f"  {DIM}contacted: {W}{dom}")

    verdicts = data.get("verdicts", {}).get("overall", {})
    if verdicts.get("malicious"):
        hit(f"{BR}MALICIOUS{RE}: urlscan flagged this URL as malicious")
    elif verdicts.get("score", 0) > 0:
        warn(f"Score: {verdicts.get('score')} — some suspicious indicators")
    else:
        hit(f"{G}Clean{RE}: no malicious indicators detected by urlscan")

    screenshot = f"https://urlscan.io/screenshots/{scan_id}.png"
    info(f"Screenshot: {C}{screenshot}{RE}")

    _db_insert_asset("urlscan", target, f"scan_id={scan_id}")
    info(f"urlscan done — {req_count} requests  {dom_count} external domains")
    return {"scan_id": scan_id, "result_url": result_u, "page": page, "verdicts": verdicts}


def mod_hibp(domain, session):
    """
    Have I Been Pwned — check if a domain appears in known data breaches.
    Uses the public /breaches endpoint filtered by domain (no API key needed).
    Source: https://haveibeenpwned.com
    """
    sect("Have I Been Pwned — Domain Breach Check")
    url = f"https://haveibeenpwned.com/api/v3/breaches"
    rs  = getattr(session, "_requests_session", None)
    if not rs:
        warn("HIBP: no requests session"); return {}

    try:
        r = rs.get(url, timeout=rs._fo_timeout, verify=False,
                   headers={"User-Agent": "FlowOsint/2.01 OSINT-Tool"})
    except Exception as e:
        err(f"HIBP request failed: {e}"); return {}

    if r.status_code != 200:
        warn(f"HIBP returned HTTP {r.status_code}"); return {}

    try:
        all_breaches = r.json()
    except Exception:
        err("HIBP: invalid JSON"); return {}

    reg_domain = extract_domain("https://" + domain)
    domain_lower = domain.lower()
    matched = []
    for breach in all_breaches:
        bd = (breach.get("Domain") or "").lower()
        if bd and (bd == domain_lower or bd == reg_domain.lower()
                   or domain_lower.endswith("." + bd)):
            matched.append(breach)

    if not matched:
        hit(f"{G}Clean{RE}: {domain} not found as a breach source in HIBP")
        info("Note: this checks if YOUR domain was breached, not if email addresses from it were leaked")
        info(f"Check individual emails at: {C}https://haveibeenpwned.com{RE}")
        return {"domain": domain, "breaches": []}

    hit(f"{BR}{len(matched)} breach(es) found associated with {domain}{RE}")
    result_list = []
    for b in matched:
        name      = b.get("Name","?")
        date      = b.get("BreachDate","?")
        pwn_count = b.get("PwnCount", 0)
        data_cls  = b.get("DataClasses", [])
        desc      = re.sub(r'<[^>]+>', '', b.get("Description",""))[:200]

        hit(f"\n  {BR}[BREACH]{RE} {W}{name}{RE}  {DIM}({date})")
        hit(f"  Records: {W}{pwn_count:,}")
        hit(f"  Data: {Y}{', '.join(data_cls[:6])}")
        info(f"  {DIM}{desc}")

        result_list.append({
            "name": name, "date": date,
            "pwn_count": pwn_count, "data_classes": data_cls
        })
        _db_insert_asset("hibp_breach", name, f"domain={domain} records={pwn_count}")

    info(f"HIBP done — {len(matched)} breach(es) found for {domain}")
    return {"domain": domain, "breaches": result_list}


_SEV_COLOR = {
    "CRITICAL": BR,
    "HIGH":     BR,
    "MEDIUM":   Y,
    "LOW":      C,
    "INFO":     DIM+W,
}

def _score_findings(all_results: dict, domain: str) -> list:
    """
    Honest risk scorer with confidence levels.

    Every finding carries:
      severity    — CRITICAL / HIGH / MEDIUM / LOW / INFO
      confidence  — CONFIRMED / LIKELY / POSSIBLE / UNVERIFIED
      caveats     — explicit list of why this might be wrong

    Key honesty rules:
    - WAF presence NEVER hides a finding — WAFs are bypassable
    - WAF IS flagged as INFO so auditor knows it exists
    - Single HTTP request checks → LIKELY at best (CDN may differ)
    - DNS records → CONFIRMED (authoritative)
    - TCP port open → CONFIRMED (handshake succeeded)
    - JS secrets (passed entropy) → CONFIRMED
    - Passive injection probes → POSSIBLE only
    """
    scored = []
    waf_detected = bool(all_results.get("waf"))

    def add(sev, conf, cat, title, detail="", fix="", caveats=None):
        scored.append({
            "severity":    sev,
            "confidence":  conf,
            "category":    cat,
            "title":       title,
            "detail":      str(detail)[:400],
            "remediation": fix,
            "caveats":     caveats or [],
        })

    waf_caveat = ([
        f"WAF/CDN detected ({', '.join(all_results['waf'])}). "
        "WAF may inject headers on some edge nodes but not all. "
        "Verify on authenticated/API paths too."
    ] if waf_detected else [])

    hdr_res = all_results.get("sec_headers", {})
    hdr_rules = {
        "Strict-Transport-Security": (
            "MEDIUM","LIKELY",
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            ["Verify: curl -sI https://{domain} | grep -i strict".format(domain=domain)]),
        "Content-Security-Policy": (
            "MEDIUM" if waf_detected else "HIGH","LIKELY",
            "Define a Content-Security-Policy to restrict script/resource origins",
            ["Some managed platforms (Squarespace/Wix) control CSP at infra level"]+waf_caveat),
        "X-Frame-Options": (
            "MEDIUM","LIKELY",
            "Add: X-Frame-Options: DENY  or use CSP frame-ancestors directive",
            ["CSP frame-ancestors is a functional equivalent — check if present"]+waf_caveat),
        "X-Content-Type-Options": (
            "LOW","LIKELY",
            "Add: X-Content-Type-Options: nosniff", waf_caveat),
        "Referrer-Policy": (
            "LOW","LIKELY",
            "Add: Referrer-Policy: strict-origin-when-cross-origin", []),
        "Permissions-Policy": (
            "LOW","LIKELY",
            "Add a Permissions-Policy header to restrict browser features",
            ["Some hosting platforms set this at infrastructure level"]),
    }
    for hdr, (sev, conf, fix, caveats) in hdr_rules.items():
        if hdr_res.get(hdr) == "MISSING":
            add(sev, conf, "Security Headers", f"Missing {hdr}",
                detail=f"Absent from HTTP response to {domain}", fix=fix, caveats=caveats)

    for f in all_results.get("email_security", {}).get("findings", []):
        add(f["severity"], "CONFIRMED", "Email Security", f["title"],
            fix=f.get("remediation",""),
            caveats=["DNS changes take up to 48h to propagate"])

    cors = all_results.get("cors", {})
    if cors.get("credentials","").lower()=="true" and cors.get("origin")=="*":
        add("CRITICAL","CONFIRMED","CORS",
            "CORS wildcard + credentials=true — authenticated request hijack possible",
            detail="Access-Control-Allow-Origin: *  +  Allow-Credentials: true",
            fix="Never combine Allow-Credentials: true with wildcard origin.",caveats=[])
    elif cors.get("origin")=="*":
        add("HIGH","LIKELY","CORS","Wildcard CORS (Access-Control-Allow-Origin: *)",
            detail="Any origin can read responses",
            fix="Restrict to trusted origins",
            caveats=["Acceptable on fully public no-auth APIs — verify endpoint purpose"])

    ssl_res = all_results.get("ssl", {})
    if ssl_res:
        cipher = ssl_res.get("cipher",[])
        if cipher and len(cipher)>=3:
            try:
                bits = int(cipher[2])
                if bits < 128:
                    add("HIGH","CONFIRMED","SSL/TLS",
                        f"Weak cipher: {cipher[0]} ({bits}-bit)",
                        detail=str(cipher),
                        fix="Use TLS 1.2+ with AES-256-GCM or ChaCha20-Poly1305",
                        caveats=["Cipher depends on client — test with: "
                                 "openssl s_client -connect {domain}:443".format(domain=domain)])
            except (ValueError,TypeError): pass
        for san in ssl_res.get("sans",[]):
            if san.startswith("*."):
                add("INFO","CONFIRMED","SSL/TLS",f"Wildcard cert: {san}",
                    fix="Use per-subdomain certs where possible",
                    caveats=["Wildcard certs are common and not inherently a vulnerability"])
    else:
        add("MEDIUM","POSSIBLE","SSL/TLS",
            "TLS handshake failed — HTTPS may not be enforced",
            fix="Ensure HTTPS enabled and HTTP redirects to HTTPS",
            caveats=["May be blocked by firewall or rate-limiting — verify manually"])

    for f in all_results.get('js',[]):
        sev = "CRITICAL" if f["type"] in (
            "AWS Access Key","AWS Secret","Private Key",
            "Stripe Key","GitHub Token","SendGrid Key") else "HIGH"
        ent = f.get("entropy",0); div = f.get('diversity',0)
        add(sev,"CONFIRMED","Secret Exposure",
            f"{f['type']} exposed in public JS file",
            detail=f"Value: {f['value'][:80]}\nSource: {f['script']}\n"
                   f"Entropy={ent:.2f} Diversity={div:.2f}",
            fix="1. Rotate credential immediately.\n"
                "2. Remove from source code.\n"
                "3. Use environment variables / secrets manager.",
            caveats=["Entropy filter applied — verify credential is still active"])

    risky = {21:("HIGH","FTP — cleartext"),23:("CRITICAL","Telnet — cleartext"),
             3306:("HIGH","MySQL exposed"),5432:("HIGH","PostgreSQL exposed"),
             27017:("HIGH","MongoDB — often unauthenticated"),
             6379:("HIGH","Redis — often unauthenticated"),
             445:("HIGH","SMB — ransomware vector"),3389:("MEDIUM","RDP exposed"),
             8080:("LOW","HTTP alt port"),8443:("LOW","HTTPS alt port")}
    for port in all_results.get("ports",[]):
        if port in risky:
            sev,note = risky[port]
            add(sev,"CONFIRMED","Network",f"Port {port} open: {note}",
                detail=f"TCP to {domain}:{port} succeeded",
                fix=f"Firewall port {port} from public access unless required.",
                caveats=(["WAF may absorb — verify from multiple IPs"] if waf_detected else []))
        else:
            add("LOW","CONFIRMED","Network",f"Port {port} open",
                fix=f"Verify port {port} requires public access",caveats=[])

    if waf_detected:
        add("INFO","CONFIRMED","Infrastructure",
            f"WAF/CDN present: {', '.join(all_results['waf'])}",
            detail="WAF reduces risk but is NOT a substitute for fixing underlying issues. "
                   "WAFs are bypassable.",
            fix="Fix underlying vulnerabilities — do not rely solely on WAF.",
            caveats=["Detection based on HTTP headers/body — custom WAF may hide its identity"])
    else:
        add("LOW","LIKELY","Infrastructure","No WAF/CDN detected",
            fix="Consider Cloudflare, AWS WAF, or ModSecurity for defence in depth",
            caveats=["WAF may be present but suppressing its signature"])

    methods = all_results.get("methods",{})
    for m,code in methods.items():
        if m in ("TRACE","PUT","DELETE") and isinstance(code,int) and code<400:
            conf = "POSSIBLE" if waf_detected else "LIKELY"
            add("MEDIUM",conf,"HTTP Methods",f"HTTP {m} accepted (→{code})",
                detail=f"Single request — {m} returned {code}",
                fix=f"Disable {m} in server config unless required.",
                caveats=(["WAF may return 200 while blocking actual execution — "
                          "verify with Burp Suite"] if waf_detected else
                         ["Verify method actually processes requests, not just returning 200"]))

    html_res = all_results.get("html",{})
    if html_res.get("comments"):
        sensitive = [c for c in html_res["comments"]
                     if any(k in c.lower() for k in
                            ["todo","password","key","secret","admin","debug",
                             "hack","fix","bug","temp","remove","internal",
                             "private","api","token","version"])]
        if sensitive:
            add("LOW","CONFIRMED","HTML",
                f"{len(sensitive)} HTML comment(s) with sensitive keywords",
                detail=" | ".join(c[:80] for c in sensitive[:3]),
                fix="Remove developer comments from production HTML",
                caveats=["Keyword match — manual review required to confirm sensitivity"])
        else:
            add("INFO","CONFIRMED","HTML",
                f"{len(html_res['comments'])} HTML comment(s) — no sensitive keywords found",
                fix="Review and remove unnecessary comments",caveats=[])
    if html_res.get("hidden"):
        sus = [h for h in html_res["hidden"]
               if any(k in h.get("name","").lower() for k in
                      ["id","token","key","hash","session","csrf","user","internal"])]
        if sus:
            add("LOW","CONFIRMED","HTML",
                f"{len(sus)} hidden input(s) with sensitive-looking names",
                detail=", ".join(f"{h['name']}={h['value'][:30]}" for h in sus[:4]),
                fix="Ensure hidden fields don't expose internal IDs or bypass logic",
                caveats=["Hidden fields are normal — "
                         "issue only if values are predictable or reusable"])

    for doc in all_results.get("doc_metadata",[]):
        if doc.get("fields"):
            sf = {k:v for k,v in doc["fields"].items()
                  if k in ("Author","LastModifiedBy","Company","Creator",
                            "AppVersion","Application")}
            if sf:
                add("LOW","CONFIRMED","Document Metadata",
                    f"Internal metadata in: {doc['url'].split('/')[-1]}",
                    detail=", ".join(f"{k}={v}" for k,v in sf.items()),
                    fix="Strip before publishing: exiftool -all= filename",
                    caveats=["Low on its own; combined with other findings aids social engineering"])

    if all_results.get("cms_context"):
        add("HIGH","CONFIRMED","CMS/API",
            f"{len(all_results['cms_context'])} sensitive key(s) in public CMS JSON endpoint",
            detail="\n".join(f"{e['key']}={e['value'][:60]}"
                             for e in all_results["cms_context"][:5]),
            fix="Restrict/disable JSON context endpoints. Check platform docs.",
            caveats=["Verify data is genuinely sensitive and not public by design"])

    live_subs = [s.get("host","") for s in (all_results.get("subdomains") or [])]
    ct_subs   = [s.get("subdomain","") for s in (all_results.get("crtsh") or [])]
    all_subs  = list(set(live_subs+ct_subs))
    if all_subs:
        risky_subs = [s for s in all_subs
                      if any(k in s.lower() for k in
                             ["dev","staging","test","admin","internal",
                              "beta","old","legacy","backup","debug","api2"])]
        if risky_subs:
            add("MEDIUM","CONFIRMED","Subdomains",
                f"{len(risky_subs)} risky subdomain(s) found (dev/staging/admin)",
                detail=", ".join(risky_subs[:10]),
                fix="Audit each. Decommission unused. Apply same security as prod.",
                caveats=["CT log entries may be historical — verify each is still live"])
        add("INFO","CONFIRMED","Subdomains",
            f"{len(all_subs)} total subdomain(s) discovered",
            detail=f"Live: {len(live_subs)}  CT logs: {len(ct_subs)}",
            fix="Maintain subdomain inventory and review periodically",caveats=[])

    for key,label in [("sqli","SQL Injection"),("xss","XSS Reflection"),("lfi","LFI")]:
        findings = all_results.get(key,[])
        if findings:
            add("HIGH","POSSIBLE","Injection",
                f"{label} indicator detected — manual confirmation required",
                detail=str(findings[0])[:200],
                fix="Verify with Burp Suite. Use parameterised queries/output encoding.",
                caveats=["Passive probe only — not confirmed exploitable",
                         "WAF may trigger false error patterns",
                         "Manual testing required to confirm"])

    if all_results.get("open_redirect"):
        add("MEDIUM","POSSIBLE","Open Redirect",
            "Open redirect parameter detected",
            detail=str(all_results["open_redirect"][0])[:200],
            fix="Validate redirect destinations against an allowlist",
            caveats=["Probe used evil.com — confirm actual redirect in browser",
                     "Some redirects are intentional (OAuth flows)"])

    sev_order  = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
    conf_order = {"CONFIRMED":0,"LIKELY":1,"POSSIBLE":2,"UNVERIFIED":3}
    scored.sort(key=lambda x:(sev_order.get(x["severity"],5),
                               conf_order.get(x["confidence"],4)))

    validated = []
    for raw in scored:
        try:
            f = Finding(**raw)
            d = f.to_dict()
            _db_insert_finding(d)
            validated.append(d)
        except Exception:
            validated.append(raw)

    return validated


def print_risk_report(scored: list, domain: str):
    sect(f"Security Findings — {domain}")

    conf_color = {"CONFIRMED":"green","LIKELY":"yellow","POSSIBLE":"cyan","UNVERIFIED":"dim white"}
    sev_color  = {"CRITICAL":"bold bright_red","HIGH":"bright_red",
                  "MEDIUM":"yellow","LOW":"cyan","INFO":"dim white"}
    counts = {}

    t = _RTable(title=f"Findings for {domain}", box=_rbox.ROUNDED,
                style="dim", header_style="bold red", title_style="bold bright_red")
    t.add_column("Sev",        style="bold",   width=10)
    t.add_column("Confidence", style="bold",   width=13)
    t.add_column("Category",   style="yellow", width=18)
    t.add_column("Title",      style="white",  width=50)

    for f in scored:
        sev  = f["severity"]
        conf = f.get("confidence","?")
        counts[sev] = counts.get(sev,0)+1
        sc = sev_color.get(sev,"white")
        cc = conf_color.get(conf,"dim white")
        t.add_row(
            f"[{sc}]{sev}[/]",
            f"[{cc}]{conf}[/]",
            f["category"],
            f["title"]
        )
    _rc.print(t)

    for f in scored:
        sev  = f["severity"]
        conf = f.get("confidence","?")
        sc   = sev_color.get(sev,"white")
        cc   = conf_color.get(conf,"dim white")

        lines = [f"[{sc}][{sev}][/] [{cc}][{conf}][/]  "
                 f"[bold white]{f['category']}[/] — [white]{f['title']}[/]"]
        if f.get("detail"):
            for line in f["detail"].splitlines():
                lines.append(f"  [dim]{line}[/]")
        if f.get("caveats"):
            for c in f["caveats"]:
                lines.append(f"  [yellow]⚠  {c}[/]")
        if f.get("remediation"):
            for line in f["remediation"].splitlines():
                lines.append(f"  [green]Fix:[/] [dim]{line}[/]")

        _rc.print(_RPanel("\n".join(lines), border_style="red", padding=(0,1)))

    W_term = tw()
    pad = " " * max(0,(W_term-62)//2)
    print(pad+"─"*62)
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        n = counts.get(sev,0)
        if n:
            clr = _SEV_COLOR.get(sev,W)
            bar = "█"*min(n*3,40)
            print(f"{pad}{clr}{sev:<12}{RE} {bar:<40} {W}{n}")
    print(pad+"─"*62)
    print()
    print(pad+f"{G}[CONFIRMED]{RE}  directly observed/verified by the tool")
    print(pad+f"{Y}[LIKELY]{RE}     single-request check, high probability")
    print(pad+f"{C}[POSSIBLE]{RE}   passive probe — manual confirmation needed")
    print(pad+f"{DIM+W}[UNVERIFIED]{RE} pattern match only — review required")
    print()

    if _DB_PATH:
        info(f"All findings saved to DB: {BR}{_DB_PATH}")
        info(f"Query example: SELECT severity,title FROM findings WHERE severity='HIGH'")



def save_report_full(target, all_results, scored, outfile=None):
    """
    Saves three files:
      1. flowoosint_DOMAIN_TS.json      — full raw data
      2. flowoosint_DOMAIN_TS.md        — Markdown bug bounty report
      3. flowoosint_DOMAIN_TS_log.txt   — complete live scan log (already written)
    """
    domain  = urlparse(target).netloc
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_fn = outfile.replace(".json","") if outfile else \
              f"flowoosint_{domain.replace('.','_')}_{ts}"

    json_path = base_fn + ".json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "tool": "FlowOsint", "version": "2.01",
            "target": target, "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "findings": scored,
            "raw_results": all_results,
        }, f, indent=2, ensure_ascii=False)

    md_path   = base_fn + ".md"
    sev_emoji = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}
    counts    = {}
    for f in scored:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    lines = []

    lines += [
        "# Security Assessment Report",
        "",
        f"> **Generated by FlowOsint v2.01** — for authorized security research only",
        "",
        "---",
        "",
        "## 1. Engagement Details",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Target URL | `{target}` |",
        f"| Domain | `{domain}` |",
        f"| Assessment Date | {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} |",
        f"| Tool | FlowOsint v2.01 |",
        f"| Assessment Type | Passive / Active Reconnaissance |",
        "",
        "---",
        "",
        "## 2. Executive Summary",
        "",
    ]

    total = len(scored)
    lines += [
        f"A total of **{total} finding(s)** were identified during this assessment.",
        "",
        "| Severity | Count | Description |",
        "|----------|-------|-------------|",
    ]
    sev_desc = {
        "CRITICAL": "Immediate exploitation risk, data exposure or full compromise",
        "HIGH":     "Significant risk, likely exploitable with moderate effort",
        "MEDIUM":   "Exploitable under certain conditions, reduces security posture",
        "LOW":      "Minor issue, defence-in-depth concern",
        "INFO":     "Informational — no direct risk but useful for attacker recon",
    }
    for sev in ("CRITICAL","HIGH","MEDIUM","LOW","INFO"):
        n = counts.get(sev, 0)
        e = sev_emoji.get(sev, "")
        lines.append(f"| {e} **{sev}** | {n} | {sev_desc[sev]} |")

    lines += ["", "---", "", "## 3. Findings", ""]

    for i, f in enumerate(scored, 1):
        sev  = f["severity"]
        e    = sev_emoji.get(sev, "")
        cat  = f["category"]
        title = f["title"]
        detail = f.get("detail", "")
        fix    = f.get("remediation", "")

        cvss_range = {
            "CRITICAL": "9.0–10.0",
            "HIGH":     "7.0–8.9",
            "MEDIUM":   "4.0–6.9",
            "LOW":      "0.1–3.9",
            "INFO":     "0.0",
        }.get(sev, "N/A")

        lines += [
            f"---",
            f"",
            f"### Finding #{i:02d} — {e} {sev}: {title}",
            f"",
            f"| Field | Details |",
            f"|-------|---------|",
            f"| **Severity** | {e} {sev} |",
            f"| **CVSS Score Range** | {cvss_range} |",
            f"| **Category** | {cat} |",
            f"| **Target** | `{target}` |",
            f"",
        ]

        if detail:
            lines += [
                "#### Evidence",
                "",
                "```",
                detail,
                "```",
                "",
            ]

        lines += [
            "#### Description",
            "",
        ]

        desc_map = {
            "Security Headers": (
                f"The HTTP response from `{target}` is missing the `{title.replace('Missing ','')}` "
                f"security header. This header is a recognised browser security control that helps "
                f"protect users from common web attacks."
            ),
            "Email Security": (
                f"The domain `{domain}` has an email authentication misconfiguration. "
                f"{title}. This allows an attacker to send emails that appear to originate "
                f"from `@{domain}`, enabling phishing and social engineering attacks against "
                f"users who trust the domain."
            ),
            "CORS": (
                f"The server at `{target}` returns a misconfigured Cross-Origin Resource Sharing "
                f"(CORS) policy. {title}. This may allow malicious websites to read responses "
                f"from this server on behalf of authenticated users."
            ),
            "SSL/TLS": (
                f"The TLS configuration on `{domain}` contains a security weakness: {title}. "
                f"This may allow an attacker with a privileged network position to weaken "
                f"or intercept encrypted communications."
            ),
            "Secret Exposure": (
                f"A sensitive credential or token was identified in a publicly accessible "
                f"JavaScript file served by `{target}`. Exposed credentials can be used by "
                f"an attacker to gain unauthorised access to third-party services or internal systems."
            ),
            "Network": (
                f"A network port is accessible from the public internet on `{domain}`. "
                f"Unnecessary open ports increase the attack surface and may expose internal "
                f"services to unauthorised access."
            ),
            "HTTP Methods": (
                f"The web server at `{target}` responds to the `{title.split(':')[-1].strip()}` "
                f"HTTP method. Dangerous HTTP methods may allow an attacker to modify server "
                f"resources or extract debug information."
            ),
            "CMS/API": (
                f"A CMS or API endpoint at `{target}` is returning sensitive application data "
                f"in a publicly accessible JSON response. This data was not intended to be exposed "
                f"and may assist an attacker in further compromising the application."
            ),
            "Document Metadata": (
                f"A publicly accessible document hosted on `{target}` contains embedded metadata "
                f"that reveals internal information such as author names, software versions, or "
                f"internal network paths. This information aids attacker reconnaissance."
            ),
            "HTML": (
                f"The HTML source of `{target}` contains information that may assist an attacker. "
                f"{title}."
            ),
            "Subdomains": (
                f"Subdomain enumeration via Certificate Transparency logs and DNS probing "
                f"identified {title.split()[0]} subdomains associated with `{domain}`. "
                f"Forgotten or staging subdomains may run outdated software or have weaker security controls."
            ),
        }
        lines.append(desc_map.get(cat, f"{title}. This was identified during automated reconnaissance of `{target}`."))
        lines.append("")

        lines += [
            "#### Steps to Reproduce",
            "",
        ]

        repro_map = {
            "Security Headers": [
                f"1. Open a terminal.",
                f"2. Run: `curl -I {target}`",
                f"3. Observe that the `{title.replace('Missing ','')}` header is absent from the response.",
            ],
            "Email Security": [
                f"1. Open a terminal with `dig` or `nslookup` installed.",
                f"2. Run: `dig TXT {domain}` to check SPF.",
                f"3. Run: `dig TXT _dmarc.{domain}` to check DMARC.",
                f"4. Observe the missing or misconfigured record as described above.",
                f"5. To verify spoofing risk, use an email spoofing test tool such as https://emkei.cz (for testing only on authorised domains).",
            ],
            "CORS": [
                f"1. Open a terminal.",
                f"2. Run: `curl -H 'Origin: https://evil.com' -I {target}`",
                f"3. Observe the `Access-Control-Allow-Origin` response header.",
                f"4. Note the value allows cross-origin access from untrusted origins.",
            ],
            "Secret Exposure": [
                f"1. Visit `{target}` in a browser.",
                f"2. Open DevTools → Sources tab.",
                f"3. Search JavaScript files for the credential pattern identified above.",
                f"4. The value can be extracted and used directly without authentication.",
            ],
            "CMS/API": [
                f"1. Open a browser or run curl.",
                f"2. Navigate to the endpoint listed in the Evidence section above.",
                f"3. Observe that sensitive data is returned without authentication.",
            ],
            "Document Metadata": [
                f"1. Download the document linked in the Evidence section.",
                f"2. Run: `exiftool <filename>` or open document properties.",
                f"3. Observe the metadata fields listed above.",
            ],
        }
        steps = repro_map.get(cat, [
            f"1. Run FlowOsint against `{target}`.",
            f"2. Select the relevant module.",
            f"3. Observe the finding described above in the output.",
        ])
        for step in steps:
            lines.append(step)
        lines.append("")

        if fix:
            lines += [
                "#### Recommended Remediation",
                "",
                fix,
                "",
            ]

        lines += [
            "#### References",
            "",
        ]
        refs_map = {
            "Security Headers":  "- https://owasp.org/www-project-secure-headers/\n- https://securityheaders.com",
            "Email Security":    "- https://dmarc.org/\n- https://www.dmarcanalyzer.com/spf/\n- https://mxtoolbox.com/dmarc.aspx",
            "CORS":              "- https://portswigger.net/web-security/cors\n- https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            "SSL/TLS":           "- https://www.ssllabs.com/ssltest/\n- https://owasp.org/www-project-transport-layer-protection-cheat-sheet/",
            "Secret Exposure":   "- https://owasp.org/www-community/vulnerabilities/Insufficient_Session-ID_Length\n- https://portswigger.net/web-security/information-disclosure",
            "Network":           "- https://nmap.org/book/port-scanning-basics.html",
            "HTTP Methods":      "- https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
            "CMS/API":           "- https://owasp.org/www-project-api-security/\n- https://portswigger.net/web-security/information-disclosure",
            "Document Metadata": "- https://www.sans.org/blog/document-metadata-the-silent-killer/\n- https://exiftool.org",
            "HTML":              "- https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
            "Subdomains":        "- https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
        }
        lines.append(refs_map.get(cat, "- https://owasp.org/www-project-web-security-testing-guide/"))
        lines.append("")

    lines += [
        "---",
        "",
        "## 4. Appendix — Scan Summary",
        "",
        "| Module | Result |",
        "|--------|--------|",
    ]
    ar = all_results
    rows = [
        ("Subdomains found",    len(ar.get("subdomains") or [])),
        ("CT log subdomains",   len(ar.get("crtsh") or [])),
        ("Paths discovered",    len(ar.get("dirbust") or [])),
        ("Links crawled",       len((ar.get("crawler") or {}).get("links",[]))),
        ("JS files analysed",   len((ar.get("crawler") or {}).get("scripts",[]))),
        ("JS secrets found",    len(ar.get("js") or [])),
        ("Forms harvested",     len((ar.get("crawler") or {}).get("forms",[]))),
        ("Emails found",        len(ar.get("emails") or [])),
        ("Open ports",          len(ar.get("ports") or [])),
        ("Documents analysed",  len(ar.get("doc_metadata") or [])),
        ("CMS keys exposed",    len(ar.get("cms_context") or [])),
        ("Email sec findings",  len((ar.get("email_security") or {}).get("findings",[]))),
        ("HTML comments",       len((ar.get("html") or {}).get("comments",[]))),
        ("Hidden inputs",       len((ar.get("html") or {}).get("hidden",[]))),
        ("Shodan open ports",   len((ar.get("shodan") or {}).get("ports",[]))),
        ("Shodan CVEs",         len((ar.get("shodan") or {}).get("vulns",[]))),
        ("VT malicious flags",  (ar.get("virustotal") or {}).get("stats",{}).get("malicious",0)),
        ("HIBP breaches",       len((ar.get("hibp") or {}).get("breaches",[]))),
        ("Wayback snapshots",   len((ar.get("wayback") or {}).get("snapshots",[]))),
    ]
    for label, val in rows:
        lines.append(f"| {label} | {val} |")

    lines += [
        "",
        "---",
        "",
        f"*Report generated by FlowOsint v2.01 on {datetime.now().strftime('%Y-%m-%d at %H:%M')}*",
        f"*For authorized security research only.*",
    ]

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    log_path = _LOG_FILE or base_fn + "_log.txt"

    sect("Reports Saved")
    hit(f"JSON report  → {BR}{json_path}")
    hit(f"BugBounty MD → {BR}{md_path}")
    hit(f"Live log     → {BR}{log_path}")
    print()
    info(f"Open {BR}{md_path}{RE} in any Markdown viewer or paste directly into HackerOne / Bugcrowd")
    return json_path, md_path


def mod_playwright_scan(base, session):
    sect("Playwright JS-Rendered Page Analysis")
    if not PLAYWRIGHT_OK:
        warn("Playwright not installed.")
        warn("Install: pip install playwright && playwright install chromium")
        return {}

    info(f"Launching headless Chromium → {base}")
    results = {"network_requests":[],"console_errors":[],"local_storage":[],
               "cookies":[],"secrets":[],"endpoints":[]}

    try:
        with _sync_pw() as pw:
            browser  = pw.chromium.launch(headless=True)
            context  = browser.new_context(
                user_agent=random.choice(UAS),
                ignore_https_errors=True,
            )
            page = context.new_page()

            def on_request(request):
                url = request.url
                results["network_requests"].append(url)
                if re.search(r'/(api|graphql|rest|v\d)/|\.json(\?|$)', url, re.I):
                    hit(f"{BR}API Request{RE}: {W}{url}")
                    results["endpoints"].append(url)

            page.on("request", on_request)

            def on_console(msg):
                if msg.type in ("error","warning"):
                    hit(f"{Y}Console {msg.type}{RE}: {DIM}{msg.text[:200]}")
                    results["console_errors"].append(msg.text[:200])

            page.on("console", on_console)

            page.goto(base, wait_until="networkidle", timeout=20000)
            page.wait_for_timeout(2000)  # extra settle time for lazy loaders

            ls = page.evaluate("() => { let d={}; for(let i=0;i<localStorage.length;i++){ let k=localStorage.key(i); d[k]=localStorage.getItem(k); } return d; }")
            for k,v in (ls or {}).items():
                hit(f"{BR}localStorage{RE}: {W}{k}{RE} = {DIM}{str(v)[:120]}")
                results["local_storage"].append({"key":k,"value":str(v)[:200]})

            for c in context.cookies():
                info(f"{C}Cookie{RE}: {c['name']}  secure={c['secure']}  httpOnly={c['httpOnly']}  sameSite={c.get('sameSite','?')}")
                results["cookies"].append(c)

            rendered_html = page.content()
            for label, pat in JS_PATTERNS.items():
                for m in re.findall(pat, rendered_html, re.IGNORECASE):
                    val = (m if isinstance(m,str) else (m[0] if m else "")).strip().strip('"\'')
                    if not val or _PLACEHOLDER_RE.match(val): continue
                    passes, ent, div = _is_real_secret(label, val)
                    if not passes: continue
                    hit(f"{BR}[Rendered] {label}{RE}: {W}{val[:120]}")
                    results["secrets"].append({"type":label,"value":val[:120],
                                               "entropy":round(ent,3)})

            browser.close()

    except Exception as e:
        err(f"Playwright scan error: {e}")

    info(f"Playwright scan done — {len(results['network_requests'])} requests intercepted | "
         f"{len(results['endpoints'])} API endpoints | "
         f"{len(results['local_storage'])} localStorage keys | "
         f"{len(results['secrets'])} secrets")
    return results


def save_report(target, data, outfile=None):
    report = {
        "tool":"FlowOsint","version":"2.01",
        "target":target,"timestamp":datetime.now().isoformat(),
        "results":data,
    }
    out = outfile or f"flowoosint_{urlparse(target).netloc.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(out,"w",encoding="utf-8") as f:
        json.dump(report,f,indent=2,ensure_ascii=False)
    sect("Report Saved")
    hit(f"Written to: {BR}{out}")
    return out


CFG = {
    "target":None,"domain":None,"session":None,
    "threads":25,"depth":2,"proxy":None,
    "wordlist":None,"outfile":None,"timeout":12,
}

def prompt_target():
    print(f"\n  {R}┌─[{W}FlowOsint{R}]─[{W}Target{R}]{RE}")
    raw = input(f"  {R}└──▶{RE} {W}URL or domain: {RE}").strip()
    if not raw: return None, None
    if not raw.startswith(("http://","https://")): raw = "https://"+raw
    return raw, urlparse(raw).netloc

def show_settings():
    print(f"""
  {R}Current Settings{RE}
  {Y}Target{RE}   : {W}{CFG['target'] or 'not set'}
  {Y}Threads{RE}  : {W}{CFG['threads']}
  {Y}Depth{RE}    : {W}{CFG['depth']}
  {Y}Timeout{RE}  : {W}{CFG['timeout']}s
  {Y}Proxy{RE}    : {W}{CFG['proxy'] or 'none'}
  {Y}Wordlist{RE} : {W}{CFG['wordlist'] or 'built-in'}
  {Y}Output{RE}   : {W}{CFG['outfile'] or 'auto-named'}
    """)
    print(f"  {R}[{W}1{R}]{RE} Change target  {R}[{W}2{R}]{RE} Threads  "
          f"{R}[{W}3{R}]{RE} Depth  {R}[{W}4{R}]{RE} Proxy  "
          f"{R}[{W}5{R}]{RE} Wordlist  {R}[{W}6{R}]{RE} Output  "
          f"{R}[{W}0{R}]{RE} Back\n")
    choice = input(f"  {R}└──▶{RE} ").strip()
    if choice == "1":
        t,d = prompt_target()
        if t:
            CFG["target"]=t
            CFG["domain"]=extract_domain(t)
            CFG["session"] = mk_session(CFG["proxy"],timeout=CFG["timeout"])
            _init_db(CFG["domain"])
    elif choice == "2":
        v = input(f"  Threads [{CFG['threads']}]: ").strip()
        if v.isdigit(): CFG["threads"]=int(v)
    elif choice == "3":
        v = input(f"  Depth [{CFG['depth']}]: ").strip()
        if v.isdigit(): CFG["depth"]=int(v)
    elif choice == "4":
        v = input("  Proxy (blank=none): ").strip()
        CFG["proxy"] = v or None
        if CFG["session"]: CFG["session"] = mk_session(CFG["proxy"],timeout=CFG["timeout"])
    elif choice == "5":
        v = input("  Wordlist path: ").strip()
        if v and os.path.isfile(v):
            with open(v,"r",encoding="utf-8",errors="ignore") as f:
                CFG["wordlist"]=[l.strip() for l in f if l.strip()]
            info(f"Loaded {len(CFG['wordlist'])} words")
        else:
            warn("File not found")
    elif choice == "6":
        v = input("  Output file (blank=auto): ").strip()
        CFG["outfile"] = v or None

def show_info():
    banner()
    lines = [
        ("01","Full Recon (All Modules)","Runs every module end-to-end"),
        ("02","Dir & File Bruteforce",   "200+ paths × common extensions, threaded"),
        ("03","Subdomain Probe",         "80+ subdomains, HTTP + HTTPS both"),
        ("04","Crawler",                 "Links, scripts, stylesheets, forms"),
        ("05","JS File Analysis",        "JS files from crawler → secret patterns"),
        ("06","HTML Comment Dump",       "Hidden inputs, comments, meta, iframes"),
        ("07","CSS Asset Extractor",     "Embedded URLs inside stylesheets"),
        ("08","Robots & Sitemap",        "robots.txt, sitemap.xml, security.txt"),
        ("09","Tech Fingerprint",        "Server, CMS, framework, cookie flags"),
        ("10","WAF / CDN Detect",        "Cloudflare, Akamai, Incapsula, F5…"),
        ("11","Header Inspector",        "Full response header dump"),
        ("12","Cookie Auditor",          "Cookie names, HttpOnly, Secure flags"),
        ("13","DNS Record Lookup",       "A, AAAA, MX, NS, TXT, SOA, CAA, SRV"),
        ("14","WHOIS Lookup",            "Registrar, creation, expiry, nameservers"),
        ("15","JS Secret Hunter",        "API keys, JWTs, AWS creds, tokens"),
        ("16","Hidden Field Dump",       "All hidden form fields + values"),
        ("17","Form Harvester",          "Action, method, all fields per form"),
        ("18","Email Harvester",         "Regex email extraction across crawled pages"),
        ("19","Open Ports Scan",         "Top 25 ports with socket probe"),
        ("20","Open Redirect Probe",     "Common redirect params + payloads"),
        ("21","Full Report Export",      "All modules → timestamped JSON"),
        ("22","SQLi Error Probe",        "Error-based SQL injection hints"),
        ("23","XSS Reflection Test",     "Reflected parameter detection"),
        ("24","LFI Path Test",           "Local file inclusion path payloads"),
        ("25","Open Ports Scan",         "Same as 19"),
        ("26","SSL/TLS Inspector",       "Cert details, cipher, SANs"),
        ("27","HTTP Methods Test",       "GET/POST/PUT/DELETE/TRACE…"),
        ("28","Clickjack / CSP Check",   "X-Frame-Options + CSP presence"),
        ("29","IP Geolocation",          "City, country, ASN, coordinates"),
        ("30","Reverse IP Lookup",       "Other hosts on same IP (via API)"),
        ("31","SPF / DMARC Check",       "Email spoofing protection audit"),
        ("32","Security Headers Audit",  "HSTS, CSP, XCTO, Referrer-Policy…"),
        ("33","CORS Policy Check",       "Wildcard / credentials misconfig"),
        ("34","Google Dork Generator",   "20 ready-to-use dorks for the domain"),
        ("50","Shodan InternetDB",       "Ports, CPEs, CVEs via internetdb.shodan.io (no key)"),
        ("51","VirusTotal Domain",       "Detection ratio & categories via VT public UI API"),
        ("52","Wayback Machine",         "Archive availability + oldest/newest snapshots"),
        ("53","GreyNoise IP Check",      "Is the IP internet noise, malicious, or clean?"),
        ("54","urlscan.io Analysis",     "Submit URL for full browser-based scan & report"),
        ("55","HaveIBeenPwned Breach",   "Check if domain appears in known breach sources"),
    ]
    print(f"\n  {BR}FlowOsint v2.01{RE} — Module Reference\n")
    for num,name,desc in lines:
        print(f"  {R}[{W}{num}{R}]{RE}  {W}{name:<28}{RE} {DIM}{desc}")
    print()


def dispatch(choice):
    target  = CFG["target"]
    domain  = CFG["domain"]
    session = CFG["session"]
    threads = CFG["threads"]
    depth   = CFG["depth"]
    wl      = CFG["wordlist"]
    results = {}

    if not target:
        t,d = prompt_target()
        if not t: warn("No target set."); return
        CFG["target"]=t; CFG["domain"]=d
        CFG["session"] = mk_session(CFG["proxy"],timeout=CFG["timeout"])
        target=t; domain=d; session=CFG["session"]
        domain = extract_domain(t)
        CFG["domain"] = domain
        _init_db(domain)

    start = time.time()

    crawl_cache = {}
    def get_crawl():
        if not crawl_cache:
            crawl_cache.update(mod_crawler(target, session, depth))
        return crawl_cache

    c = choice.strip()

    if c == "01":   # Full recon
        results["fingerprint"]    = mod_fingerprint(target, session)
        results["waf"]            = mod_waf(target, session)
        results["sec_headers"]    = mod_sec_headers(target, session)
        results["cors"]           = mod_cors(target, session)
        results["ssl"]            = mod_ssl(domain)
        results["robots"]         = mod_robots(target, session)
        results["html"]           = mod_html(target, session)
        cr = get_crawl()
        results["crawler"]        = cr
        results["js"]             = mod_js(cr["scripts"], session)
        results["css"]            = mod_css(cr["styles"], session)
        results["emails"]         = mod_emails(cr["links"], session)
        results["doc_metadata"]   = mod_doc_metadata(cr["links"], session)
        results["dirbust"]        = mod_dirbust(target, session, threads, wl)
        results["subdomains"]     = mod_subdomains(domain, session)
        results["crtsh"]          = mod_crtsh(domain, session)
        results["email_security"] = mod_email_security(domain)
        results["cms_context"]    = mod_cms_context(target, session)
        results["dns"]            = mod_dns(domain)
        results["whois"]          = mod_whois(domain)
        results["ports"]          = mod_ports(domain)
        results["geoip"]          = mod_geoip(domain, session)
        results["dorks"]          = mod_dorks(domain)
        results["shodan"]         = mod_shodan(domain, session)
        results["greynoise"]      = mod_greynoise(domain, session)
        results["virustotal"]     = mod_virustotal(domain, session)
        results["wayback"]        = mod_wayback(domain, session)
        results["hibp"]           = mod_hibp(domain, session)
    elif c == "02": results["dirbust"]      = mod_dirbust(target, session, threads, wl)
    elif c == "03": results["subdomains"]   = mod_subdomains(domain, session)
    elif c == "04": results["crawler"]      = mod_crawler(target, session, depth)
    elif c == "05":
        cr=get_crawl(); results["crawler"]=cr
        results["js"] = mod_js(cr["scripts"], session)
    elif c == "06": results["html"]         = mod_html(target, session)
    elif c == "07":
        cr=get_crawl(); results["css"] = mod_css(cr["styles"], session)
    elif c == "08": results["robots"]       = mod_robots(target, session)
    elif c == "09": results["fingerprint"]  = mod_fingerprint(target, session)
    elif c == "10": results["waf"]          = mod_waf(target, session)
    elif c == "11": results["fingerprint"]  = mod_fingerprint(target, session)
    elif c == "12": results["fingerprint"]  = mod_fingerprint(target, session)
    elif c == "13": results["dns"]          = mod_dns(domain)
    elif c == "14": results["whois"]        = mod_whois(domain)
    elif c == "15":
        cr=get_crawl(); results["js"] = mod_js(cr["scripts"], session)
    elif c == "16": results["html"]         = mod_html(target, session)
    elif c == "17":
        cr=get_crawl(); results["forms"] = cr.get("forms",[])
    elif c == "18":
        cr=get_crawl(); results["emails"] = mod_emails(cr["links"], session)
    elif c == "19": results["ports"]        = mod_ports(domain)
    elif c == "20": results["open_redirect"]= mod_open_redirect(target, session)
    elif c == "21":
        if not results:
            warn("No scan results in this session yet — run a module first (e.g. 01 for full recon)")
            return
        scored = _score_findings(results, domain)
        print_risk_report(scored, domain)
        save_report_full(target, results, scored, CFG["outfile"])
        return
    elif c == "22": results["sqli"]         = mod_sqli(target, session)
    elif c == "23": results["xss"]          = mod_xss(target, session)
    elif c == "24": results["lfi"]          = mod_lfi(target, session)
    elif c == "25": results["ports"]        = mod_ports(domain)
    elif c == "26": results["ssl"]          = mod_ssl(domain)
    elif c == "27": results["methods"]      = mod_methods(target, session)
    elif c == "28":
        r = get(session, target)
        xfo = r.headers.get("X-Frame-Options","") if r else ""
        csp = r.headers.get("Content-Security-Policy","") if r else ""
        hit(f"X-Frame-Options: {W}{xfo or 'MISSING — clickjacking possible'}")
        hit(f"CSP: {W}{csp[:120] or 'MISSING'}")
        results["clickjack"] = {"xfo":xfo,"csp":csp}
    elif c == "29": results["geoip"]        = mod_geoip(domain, session)
    elif c == "30":
        try:
            ip = socket.gethostbyname(domain)
            r  = get(session, f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
            if r:
                for line in r.text.splitlines()[:40]:
                    hit(f"{Y}Reverse IP{RE}: {W}{line}")
        except Exception as e: err(str(e))
    elif c == "31": results["spf_dmarc"]    = mod_spf_dmarc(domain)
    elif c == "32": results["sec_headers"]  = mod_sec_headers(target, session)
    elif c == "33": results["cors"]         = mod_cors(target, session)
    elif c == "34": results["dorks"]        = mod_dorks(domain)
    elif c == "35": results["dorks"]        = mod_dorks(domain)
    elif c in ("36","hash"):
        val = input(f"  {R}└──▶{RE} String to hash: ").strip()
        import hashlib
        for algo in ["md5","sha1","sha256","sha512"]:
            h = hashlib.new(algo, val.encode()).hexdigest()
            hit(f"{Y}{algo:8}{RE}: {W}{h}")
    elif c in ("37","b64"):
        import base64
        val = input(f"  {R}└──▶{RE} Encode or decode? [e/d]: ").strip().lower()
        s   = input(f"  {R}└──▶{RE} String: ").strip()
        try:
            if val == "d": hit(f"Decoded: {W}{base64.b64decode(s).decode()}")
            else:          hit(f"Encoded: {W}{base64.b64encode(s.encode()).decode()}")
        except Exception as e: err(str(e))
    elif c in ("38","urls"):
        cr=get_crawl()
        for u in cr["links"]: info(u)
    elif c in ("40","batch"):
        print(f"  {R}└──▶{RE} Enter URLs one per line, empty line to finish:")
        urls = []
        while True:
            u = input("    ").strip()
            if not u: break
            if not u.startswith("http"): u = "https://"+u
            urls.append(u)
        for u in urls:
            r = get(session, u)
            if r: hit(f"[{r.status_code}] {W}{u}  {DIM}({len(r.content)} B)")
            else: warn(f"unreachable: {u}")
    elif c == "41": results["crtsh"]          = mod_crtsh(domain, session)
    elif c == "42": results["email_security"] = mod_email_security(domain)
    elif c == "43": results["cms_context"]    = mod_cms_context(target, session)
    elif c == "44":
        cr=get_crawl(); results["doc_metadata"] = mod_doc_metadata(cr["links"], session)
    elif c == "45":
        scored = _score_findings(results, domain)
        print_risk_report(scored, domain)
        save_report_full(target, results, scored, CFG["outfile"])
        return
    elif c == "46":
        results["playwright"] = mod_playwright_scan(target, session)
    elif c == "47":
        cr = mod_crawler(target, session, CFG["depth"], js_render=True)
        results["crawler"] = cr
        results["js"]      = mod_js(cr["scripts"], session)
    elif c == "48":
        print(f"\n  {R}┌─[{W}DuckDB Query{R}]{RE}")
        print(f"  {DIM}Tables: findings, assets{RE}")
        print(f"  {DIM}Example: SELECT * FROM findings WHERE severity='HIGH'{RE}")
        sql = input(f"  {R}└──▶{RE} SQL> ").strip()
        if sql: db_query(sql)
        return
    elif c == "49":
        sect("Trafilatura — Clean Text Extraction")
        if not TRAFILATURA_OK:
            warn("trafilatura not installed: pip install trafilatura"); return
        r = get(session, target)
        if r:
            text = _trafilatura.extract(r.text, include_comments=True,
                                         include_tables=True,
                                         include_links=True) or ""
            if text:
                hit(f"Extracted {len(text)} chars of clean text")
                print(f"\n{DIM}{text[:3000]}{RE}\n")
                results["trafilatura_text"] = text[:5000]
            else:
                warn("trafilatura extracted no content from this page")
    elif c == "50": results["shodan"]      = mod_shodan(domain, session)
    elif c == "51": results["virustotal"]  = mod_virustotal(domain, session)
    elif c == "52": results["wayback"]     = mod_wayback(domain, session)
    elif c == "53": results["greynoise"]   = mod_greynoise(domain, session)
    elif c == "54": results["urlscan"]     = mod_urlscan(target, session)
    elif c == "55": results["hibp"]        = mod_hibp(domain, session)
    elif c in ("60","username"):
        target_username = input(f"  {R}└──▶{RE} {W}Username to search: {RE}").strip()
        if not target_username:
            warn("No username provided")
        else:
            results["username_search"] = mod_username_search(target_username, session)

    elif c in ("61","emailosint"):
        target_email = input(f"  {R}└──▶{RE} {W}Email address: {RE}").strip()
        if not target_email:
            warn("No email provided")
        else:
            results["email_osint"] = mod_email_osint(target_email, session)

    elif c in ("62","githubuser"):
        gh_username = input(f"  {R}└──▶{RE} {W}GitHub username: {RE}").strip()
        if not gh_username:
            warn("No username provided")
        else:
            results["github_user"] = mod_github_user(gh_username, session)
    else:
        warn(f"Option '{c}' not recognised")
        return

    elapsed = time.time()-start
    sect(f"Scan Complete — {elapsed:.1f}s")

    stat_map = [
        ("paths found",      len(results.get("dirbust",[]))),
        ("links",            len(results.get("crawler",{}).get("links",[]))),
        ("scripts",          len(results.get("crawler",{}).get("scripts",[]))),
        ("forms",            len(results.get("crawler",{}).get("forms",[]))),
        ("JS findings",      len(results.get("js",[]))),
        ("subdomains",       len(results.get("subdomains",[]))),
        ("crt.sh subdomains",len(results.get("crtsh",[]))),
        ("emails",           len(results.get("emails",[]))),
        ("open ports",       len(results.get("ports",[]))),
        ("hidden inputs",    len(results.get("html",{}).get("hidden",[]))),
        ("HTML comments",    len(results.get("html",{}).get("comments",[]))),
        ("doc metadata",     len(results.get("doc_metadata",[]))),
        ("email findings",   len(results.get("email_security",{}).get("findings",[]))),
        ("CMS keys exposed", len(results.get("cms_context",[]))),
        ("Shodan CVEs",      len(results.get("shodan",{}).get("vulns",[]))),
        ("Shodan ports",     len(results.get("shodan",{}).get("ports",[]))),
        ("VT detections",    (results.get("virustotal",{}).get("stats",{}) or {}).get("malicious",0)),
        ("HIBP breaches",    len((results.get("hibp",{}) or {}).get("breaches",[]))),
        ("Wayback snaps",    len(results.get("wayback",{}).get("snapshots",[]))),
        ("urlscan scans",    1 if results.get("urlscan",{}).get("scan_id") else 0),
    ]
    W_term = tw()
    pad = " " * max(0,(W_term-50)//2)
    for k,v in stat_map:
        if v:
            print(f"{pad}{BR}{v:>5}{RE}  {W}{k}")

    if results:
        scored = _score_findings(results, domain)
        print_risk_report(scored, domain)
        save_report_full(target, results, scored, CFG["outfile"])


def main():
    banner()
    time.sleep(0.3)

    log_path = f"flowoosint_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}_log.txt"
    _set_log_file(log_path)
    info(f"Live log: {BR}{log_path}{RE}  (all output saved here in real time)")

    for msg in ["Initialising modules","Loading wordlists","Ready"]:
        sp = Spinner(msg).start()
        time.sleep(0.6)
        sp.stop(msg)
    time.sleep(0.2)

    CFG["session"] = mk_session(timeout=CFG["timeout"])

    while True:
        print()
        print(ctr(f"{R}┌{'─'*30}┐{RE}"))
        print(ctr(f"{R}│{RE}  {Y}What do you want to do today?{RE}   {R}│{RE}"))
        print(ctr(f"{R}├{'─'*30}┤{RE}"))
        print(ctr(f"{R}│{RE}  {W}[1]{RE} Web / Domain Recon         {R}│{RE}"))
        print(ctr(f"{R}│{RE}  {W}[2]{RE} Social Media & Person OSINT {R}│{RE}"))
        print(ctr(f"{R}│{RE}  {W}[0]{RE} Exit                        {R}│{RE}"))
        print(ctr(f"{R}└{'─'*30}┘{RE}"))
        print()
        mode = input(
            f"  {R}┌─[{W}FlowOsint{R}]─[{W}v2.01{R}]{RE}\n"
            f"  {R}└──▶{RE} {W}Select mode: {RE}"
        ).strip()

        if mode in ("0","00","exit","quit","q"):
            sep()
            print(ctr(f"{BR}Thank you for using FlowOsint. Stay ethical.{RE}"))
            sep()
            time.sleep(0.5)
            break
        elif mode == "1":
            _web_recon_loop()
        elif mode == "2":
            _social_loop()
        else:
            warn("Pick 1 or 2")
            banner()


def _web_recon_loop():
    while True:
        banner()
        draw_menu()

        if CFG["target"]:
            print(ctr(f"{DIM}{W}target: {BR}{CFG['target']}{RE}"))

        raw = input(
            f"  {R}┌─[{W}FlowOsint{R}]─[{W}Web Recon{R}]{RE}\n"
            f"  {R}└──▶{RE} {W}Select option: {RE}"
        ).strip().lower()

        if raw in ("00","0","exit","quit","q","back","b"):
            banner()
            break

        elif raw in ("n","next"):
            _current_page[0] = (_current_page[0] % 4) + 1

        elif raw in ("i","info"):
            show_info()
            input(f"\n  {DIM}Press Enter to return...{RE}")

        elif raw in ("s","98","settings"):
            banner()
            show_settings()
            time.sleep(0.5)

        else:
            real = _COMPACT_REMAP.get(raw, raw)
            try:
                dispatch(real)
            except KeyboardInterrupt:
                print(f"\n  {Y}Scan interrupted{RE}")
            except Exception as e:
                err(f"Module error: {e}")
                import traceback; traceback.print_exc()
            input(f"\n  {DIM}Press Enter to return to menu...{RE}")


def _social_loop():
    session = CFG["session"]
    while True:
        banner()
        print()
        print(ctr(f"{R}┌{'─'*34}┐{RE}"))
        print(ctr(f"{R}│{RE}  {BR}{BOLD}Social Media & Person OSINT{RE}      {R}│{RE}"))
        print(ctr(f"{R}├{'─'*34}┤{RE}"))
        print(ctr(f"{R}│{RE}  {R}[{W}60{R}]{RE} Username Search (30+ platforms) {R}│{RE}"))
        print(ctr(f"{R}│{RE}  {R}[{W}61{R}]{RE} Email OSINT                     {R}│{RE}"))
        print(ctr(f"{R}│{RE}  {R}[{W}62{R}]{RE} GitHub User OSINT               {R}│{RE}"))
        print(ctr(f"{R}│{RE}  {R}[{W}00{R}]{RE} Back                            {R}│{RE}"))
        print(ctr(f"{R}└{'─'*34}┘{RE}"))
        print()

        raw = input(
            f"  {R}┌─[{W}FlowOsint{R}]─[{W}Social OSINT{R}]{RE}\n"
            f"  {R}└──▶{RE} {W}Select option: {RE}"
        ).strip().lower()

        if raw in ("00","0","back","b","exit","q"):
            banner()
            break

        elif raw in ("60","username"):
            target_username = input(f"  {R}└──▶{RE} {W}Username to search: {RE}").strip()
            if not target_username:
                warn("No username provided")
            else:
                mod_username_search(target_username, session)
            input(f"\n  {DIM}Press Enter to return...{RE}")

        elif raw in ("61","emailosint"):
            target_email = input(f"  {R}└──▶{RE} {W}Email address: {RE}").strip()
            if not target_email:
                warn("No email provided")
            else:
                mod_email_osint(target_email, session)
            input(f"\n  {DIM}Press Enter to return...{RE}")

        elif raw in ("62","githubuser"):
            gh_username = input(f"  {R}└──▶{RE} {W}GitHub username: {RE}").strip()
            if not gh_username:
                warn("No username provided")
            else:
                mod_github_user(gh_username, session)
            input(f"\n  {DIM}Press Enter to return...{RE}")

        else:
            warn(f"Option '{raw}' not recognised")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {BR}Interrupted — goodbye.{RE}\n")
    except Exception as e:
        print(f"\n  [FATAL] {e}")
        import traceback; traceback.print_exc()
    finally:
        if os.name == "nt":
            input("\n  Press Enter to exit...")