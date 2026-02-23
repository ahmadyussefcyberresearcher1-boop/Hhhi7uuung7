PATTERNS = {
    'OpenAI_API_Key': ('sk-[a-zA-Z0-9]{20,60}T3BlbkFJ[a-zA-Z0-9]{20,60}|sk-proj-[a-zA-Z0-9\\-_]{40,100}', 'Critical'),
    'Anthropic_Claude_Key': ('sk-ant-api\\d{2}-[a-zA-Z0-9\\-_]{80,110}', 'Critical'),
    'Grok_xAI_Key': ('xai-[a-zA-Z0-9]{40,80}', 'Critical'),
    'Google_Gemini_Key': ('AIza[0-9A-Za-z\\-_]{35}', 'Critical'),
    'HuggingFace_Token': ('hf_[a-zA-Z0-9]{30,50}', 'High'),
    'AWS_Access_Key_ID': ('(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}', 'Critical'),
    'AWS_Secret_Key': ('(?i)aws[_\\-\\s.]{0,10}secret[_\\-\\s.]{0,10}(access)?[_\\-\\s.]{0,5}key["\\\'`\\s]*[:=]["\\\'`\\s]*([A-Za-z0-9/+=]{40})', 'Critical'),
    'GitHub_PAT_Classic': ('ghp_[a-zA-Z0-9]{36}', 'Critical'),
    'GitHub_OAuth_Token': ('gho_[a-zA-Z0-9]{36}', 'Critical'),
    'GitHub_App_Token': ('(?:ghu|ghs)_[a-zA-Z0-9]{36}', 'Critical'),
    'GitHub_Fine_Grained_PAT': ('github_pat_[a-zA-Z0-9_]{82}', 'Critical'),
    'Stripe_Secret_Key': ('sk_live_[0-9a-zA-Z]{24,}', 'Critical'),
    'Stripe_Test_Key': ('sk_test_[0-9a-zA-Z]{24,}', 'High'),
    'Stripe_Publishable_Key': ('pk_live_[0-9a-zA-Z]{24,}', 'Medium'),
    'Stripe_Restricted_Key': ('rk_live_[0-9a-zA-Z]{24,}', 'Critical'),
    'Slack_Bot_Token': ('xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'Critical'),
    'Slack_User_Token': ('xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}', 'Critical'),
    'Slack_Webhook_URL': ('https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,11}/[a-zA-Z0-9_]{24}', 'High'),
    'SendGrid_API_Key': ('SG\\.[a-zA-Z0-9\\-_]{22}\\.[a-zA-Z0-9\\-_]{43}', 'Critical'),
    'Mailgun_API_Key': ('key-[0-9a-zA-Z]{32}', 'High'),
    'Twilio_Auth_Token': ('(?i)twilio[^"\\\']{0,30}auth[_\\-\\s]*token["\\\'`\\s]*[:=]["\\\'`\\s]*([a-f0-9]{32})', 'Critical'),
    'JSON_Web_Token': ('eyJ[a-zA-Z0-9\\-_=]{10,}\\.eyJ[a-zA-Z0-9\\-_=]{10,}\\.[a-zA-Z0-9\\-_.+/=]{10,}', 'High'),
    'MongoDB_URI': ('mongodb(?:\\+srv)?://[a-zA-Z0-9_%\\-]+:[a-zA-Z0-9_%\\-@!$&()*+,;=]{8,}@[a-zA-Z0-9\\-._]+', 'Critical'),
    'PostgreSQL_URI': ('postgres(?:ql)?://[a-zA-Z0-9_%\\-]+:[a-zA-Z0-9_%\\-@!$&()*+,;=]{8,}@[a-zA-Z0-9\\-._]+', 'Critical'),
    'MySQL_URI': ('mysql://[a-zA-Z0-9_%\\-]+:[a-zA-Z0-9_%\\-@!$&()*+,;=]{8,}@[a-zA-Z0-9\\-._]+', 'Critical'),
    'Redis_URI': ('redis://[a-zA-Z0-9_%\\-]+:[a-zA-Z0-9_%\\-@!$&()*+,;=]{8,}@[a-zA-Z0-9\\-._]+', 'High'),
    'RSA_Private_Key': ('-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Critical'),
    'PGP_Private_Key': ('-----BEGIN PGP PRIVATE KEY BLOCK-----', 'Critical'),
    'DigitalOcean_Token': ('dop_v1_[a-f0-9]{64}', 'Critical'),
    'NPM_Token': ('npm_[a-zA-Z0-9]{36}', 'High'),
    'Shopify_Access_Token': ('shpat_[a-fA-F0-9]{32}', 'Critical'),
    'Shopify_Storefront_Token': ('shpss_[a-fA-F0-9]{32}', 'High'),
    'Discord_Webhook': ('https://discord(?:app)?\\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_\\-]{60,}', 'Medium'),
    'Telegram_Bot_Token': ('(?<![a-zA-Z0-9])\\d{8,10}:[a-zA-Z0-9_\\-]{35}(?![a-zA-Z0-9])', 'High'),
    'Sentry_DSN': ('https://[a-f0-9]{32}@[a-z0-9]+\\.ingest\\.sentry\\.io/[0-9]+', 'Medium'),
    'Mapbox_Token': ('pk\\.[a-zA-Z0-9]{60,}\\.[a-zA-Z0-9\\-_]{22}', 'Medium'),
    'Linear_API_Key': ('lin_api_[a-zA-Z0-9]{40}', 'High'),
    'Notion_Token': ('secret_[a-zA-Z0-9]{43}', 'High'),
    'Ethereum_Private_Key': ('0x[a-fA-F0-9]{64}', 'Critical'),
    'Infura_Project_ID': ('infura\\.io/v3/([a-f0-9]{32})', 'High'),
    'Firebase_API_Key': ('(?i)firebase[^"\\\']{0,20}["\\\'`]AIza[0-9A-Za-z\\-_]{35}["\\\'`]', 'Critical'),
    'Generic_Password': ('(?i)(?:password|passwd|pwd)\\s*[:=]\\s*["\\\']([^"\\\']{8,40})["\\\']', 'High'),
    'Generic_Secret_Key': ('(?i)secret[_\\-]key\\s*[:=]\\s*["\\\']([^"\\\']{16,64})["\\\']', 'High'),
    'Generic_API_Key': ('(?i)api[_\\-]key\\s*[:=]\\s*["\\\']([^"\\\']{16,64})["\\\']', 'Medium'),
    'SMTP_Password': ('(?i)smtp[^"\\\']{0,20}(?:pass|password)\\s*[:=]\\s*["\\\']([^"\\\']{6,40})["\\\']', 'High'),
}

# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
AdvancedJS_SecretsHunter.py v4.2
Pattern-only secret scanner. No API calls.
Output: results/TARGET/findings/secrets.js

  AWS_Access_Key_ID: AKIAXXXXXXXX
  GitHub_PAT_Classic: ghp_XXXXXXXX
  Stripe_Secret_Key: sk_live_XXXXXXXX

RUN:
  python3 AdvancedJS_SecretsHunter.py -t targets.txt -o results/ --threads 50
  python3 AdvancedJS_SecretsHunter.py --single example.com
"""

import os, re, sys, json, time, random, hashlib
import logging, argparse, shutil, subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.logging import RichHandler
except ImportError as e:
    print("[!] Missing: " + str(e) + "\nRun: pip install requests rich")
    sys.exit(1)

BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
CHAT_ID   = "YOUR_CHAT_ID_HERE"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

HIGH_VALUE_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".json", ".env", ".map", ".bak", ".old", ".backup",
    ".config", ".yml", ".yaml", ".properties", ".xml",
}

HIGH_VALUE_PATHS = [
    "/api/", "/config/", "/secrets/", "/admin/", "/private/",
    "/env/", "/settings/", "/auth/", "/oauth/", "/token/",
    "/.env", "/wp-config", "/credentials", "/backup/",
]

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEV_COLOR = {
    "Critical": "bold red",
    "High":     "red",
    "Medium":   "yellow",
    "Low":      "green",
}

console = Console()
logging.basicConfig(
    level=logging.INFO, format="%(message)s",
    handlers=[
        RichHandler(rich_tracebacks=True, console=console),
        logging.FileHandler("hunter.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("Hunter")


# --- FALSE POSITIVE FILTERS ---------------------------------------------------

FP_CONTEXT_PATTERNS = [
    re.compile(r"(?:href|src|action|data-src|url)\s*=", re.I),
    re.compile(r"archive\.org"),
    re.compile(r"wayback"),
    re.compile(r"sourceMappingURL"),
]

HASH_RE = re.compile(r"^[a-f0-9]{32,}$")

PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:your[_-]?|example[_-]?|test[_-]?|dummy[_-]?|changeme|placeholder|xxx+|000+|aaa+)",
)

MIN_LENGTHS = {
    "Generic_Password":   8,
    "Generic_Secret_Key": 16,
    "Generic_API_Key":    16,
    "SMTP_Password":      6,
}

DB_TYPES = {
    "MongoDB_URI", "PostgreSQL_URI", "MySQL_URI", "Redis_URI",
    "Slack_Webhook_URL", "Discord_Webhook", "Sentry_DSN",
    "Infura_Project_ID", "Firebase_API_Key",
}


def is_fp(secret_type, value, context):
    """Return True if this looks like a false positive."""
    min_len = MIN_LENGTHS.get(secret_type, 12)
    if len(value) < min_len:
        return True
    if HASH_RE.match(value.lower()):
        return True
    if PLACEHOLDER_RE.search(value):
        return True
    if "/" in value and secret_type not in DB_TYPES:
        return True
    for pat in FP_CONTEXT_PATTERNS:
        if pat.search(context):
            if re.search("/" + re.escape(value[:8]), context):
                return True
    return False


# --- UTILITIES ----------------------------------------------------------------


def banner():
    console.print(Panel.fit(
        "[bold cyan]AdvancedJS SecretsHunter v4.2[/bold cyan]\n"
        "[dim]Pattern-only | No API calls | Clean JS output[/dim]",
        title="[bold green]Secrets Hunter[/bold green]",
        border_style="bright_blue",
    ))


def random_ua():
    return random.choice(USER_AGENTS)


def random_delay(mn=0.2, mx=1.0):
    time.sleep(random.uniform(mn, mx))


def is_tool(tool):
    try:
        return subprocess.run(["which", tool], capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


def create_session():
    s = requests.Session()
    retry = Retry(
        total=3, backoff_factor=1.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    s.mount("http://",  HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers.update({
        "User-Agent": random_ua(),
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
    })
    return s


def setup_dirs(base, target):
    root = Path(base) / target
    dirs = {
        "root":      root,
        "downloads": root / "downloaded_files",
        "findings":  root / "findings",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def cleanup_dl(dirs):
    dl = dirs.get("downloads")
    if dl and dl.exists():
        try:
            shutil.rmtree(dl)
        except Exception:
            pass


# --- URL COLLECTION -----------------------------------------------------------


def run_cmd(cmd, timeout=120):
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        if r.stdout:
            return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    except Exception:
        pass
    return []


def collect_urls(domain, deep=False):
    log.info("[bold blue]Collecting URLs: " + domain + "[/bold blue]")
    cmds = []
    if is_tool("waybackurls"): cmds.append(["waybackurls", domain])
    if is_tool("gau"):         cmds.append(["gau", "--subs", "--providers=all", domain])
    if is_tool("gauplus"):     cmds.append(["gauplus", "-t", "5", domain])
    if is_tool("katana"):      cmds.append(["katana", "-u", "https://" + domain, "-jc", "-d", "3", "-silent"])
    if is_tool("hakrawler"):   cmds.append(["hakrawler", "-subs", "-u", "https://" + domain])
    if is_tool("getJS"):       cmds.append(["getJS", "--url", "https://" + domain, "--complete"])
    if deep and is_tool("waymore"): cmds.append(["waymore", "-i", domain, "-mode", "U"])
    if not cmds:
        log.warning("No tools found -- basic crawl")
        return _basic_crawl(domain)
    urls = set()
    with ThreadPoolExecutor(max_workers=len(cmds)) as ex:
        futs = {ex.submit(run_cmd, c): c[0] for c in cmds}
        for fut in as_completed(futs):
            try:
                urls.update(fut.result())
            except Exception:
                pass
    log.info("  Found " + str(len(urls)) + " URLs")
    return urls


def _basic_crawl(domain):
    urls = set()
    sess = create_session()
    for scheme in ["https", "http"]:
        try:
            r = sess.get(scheme + "://" + domain, timeout=10)
            for m in re.finditer(
                r"src=[\"'](/[^\"']*\.js)[\"']", r.text
            ):
                urls.add(scheme + "://" + domain + m.group(1))
            break
        except Exception:
            continue
    return urls


def filter_urls(urls):
    out = []
    for url in urls:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            continue
        path = urlparse(url).path.lower()
        if (any(path.endswith(e) or e + "?" in path for e in HIGH_VALUE_EXTENSIONS)
                or any(p in path for p in HIGH_VALUE_PATHS)):
            out.append(url)
    return list(set(out))


# --- DOWNLOAD -----------------------------------------------------------------


def download_one(url, save_dir, session):
    safe = re.sub(r"[^\w\-_.]", "_", urlparse(url).path.lstrip("/"))[-150:]
    if not safe:
        safe = hashlib.md5(url.encode()).hexdigest()[:16]
    sp = save_dir / safe
    if sp.exists() and sp.stat().st_size > 0:
        return (sp, url)
    for attempt in range(3):
        try:
            session.headers["User-Agent"] = random_ua()
            r = session.get(url, timeout=10, stream=True)
            if r.status_code == 200 and r.content:
                with open(sp, "wb") as f:
                    for chunk in r.iter_content(8192):
                        f.write(chunk)
                return (sp, url)
            if r.status_code in (403, 404):
                break
        except requests.RequestException:
            if attempt < 2:
                time.sleep(random.uniform(1, 2))
    return None


def download_all(urls, save_dir, workers=20):
    done, url_map = [], {}
    sess = create_session()
    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"),
        BarColumn(), TaskProgressColumn(), console=console,
    ) as prog:
        task = prog.add_task(
            "[cyan]Downloading " + str(len(urls)) + " files...", total=len(urls)
        )
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(download_one, u, save_dir, sess): u for u in urls}
            for fut in as_completed(futs):
                prog.advance(task)
                try:
                    res = fut.result()
                    if res:
                        done.append(res[0])
                        url_map[str(res[0])] = res[1]
                except Exception:
                    pass
    log.info("  Downloaded " + str(len(done)) + "/" + str(len(urls)) + " files")
    return done, url_map


# --- SCAN ---------------------------------------------------------------------


def scan_file(file_path, source_url):
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    results = []
    seen = set()
    for name, (pattern, severity) in PATTERNS.items():
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                value = m.group(0)
                for g in range(m.lastindex or 0, 0, -1):
                    try:
                        gv = m.group(g)
                        if gv and len(gv) >= 8:
                            value = gv
                            break
                    except IndexError:
                        pass
                value = value.strip()
                dk = name + ":" + value
                if dk in seen:
                    continue
                seen.add(dk)
                cs  = max(0, m.start() - 100)
                ce  = min(len(content), m.end() + 100)
                ctx = content[cs:ce].replace("\n", " ").strip()
                if is_fp(name, value, ctx):
                    log.debug("  [FP] " + name + ": " + value[:20])
                    continue
                line_num = content[:m.start()].count("\n") + 1
                results.append({
                    "type":       name,
                    "severity":   severity,
                    "value":      value,
                    "source_url": source_url,
                    "file":       str(file_path),
                    "line":       line_num,
                    "context":    ctx[:250],
                })
        except re.error:
            continue
    return results


def scan_all(file_paths, url_map, workers=30):
    log.info("[bold green]Scanning " + str(len(file_paths)) + " files...[/bold green]")
    valid = [fp for fp in file_paths if fp.exists() and fp.stat().st_size > 0]
    if not valid:
        return []
    all_results = []
    nw = min(workers, (os.cpu_count() or 4) * 2, len(valid))
    with Progress(
        SpinnerColumn(), TextColumn("{task.description}"),
        BarColumn(), TaskProgressColumn(), console=console,
    ) as prog:
        task = prog.add_task("[green]Scanning...", total=len(valid))
        with ThreadPoolExecutor(max_workers=nw) as ex:
            fmap = {
                ex.submit(scan_file, fp, url_map.get(str(fp), "unknown")): fp
                for fp in valid
            }
            for fut in as_completed(fmap):
                prog.advance(task)
                try:
                    all_results.extend(fut.result())
                except Exception as e:
                    log.debug("Scan error: " + str(e))
    log.info("  Found " + str(len(all_results)) + " secrets")
    return all_results


# --- SAVE ---------------------------------------------------------------------


def save_results(dirs, target, all_urls, interesting, secrets):
    ss = sorted(secrets, key=lambda x: SEV_ORDER.get(x.get("severity", "Low"), 3))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    js = [
        "// ============================================",
        "// SecretsHunter v4.2",
        "// Target : " + target,
        "// Date   : " + now,
        "// Secrets: " + str(len(ss)),
        "// ============================================",
        "",
    ]
    cur_sev = None
    for s in ss:
        if s["severity"] != cur_sev:
            cur_sev = s["severity"]
            js.append("// [" + cur_sev + "]")
        js.append(s["type"] + ": " + s["value"])
        js.append("  // Source : " + s["source_url"])
        js.append("  // Line   : " + str(s["line"]))
        js.append("")
    out = dirs["findings"] / "secrets.js"
    out.write_text("\n".join(js), encoding="utf-8")
    with open(dirs["findings"] / "secrets.json", "w", encoding="utf-8") as f:
        json.dump({"target": target, "date": now,
                   "count": len(ss), "secrets": ss},
                  f, indent=2, ensure_ascii=False)
    (dirs["root"] / "all_urls.txt").write_text(
        "\n".join(sorted(set(all_urls))), encoding="utf-8")
    (dirs["root"] / "interesting_files.txt").write_text(
        "\n".join(sorted(set(interesting))), encoding="utf-8")
    crit = sum(1 for s in ss if s["severity"] == "Critical")
    high = sum(1 for s in ss if s["severity"] == "High")
    med  = sum(1 for s in ss if s["severity"] == "Medium")
    summary = [
        "Target   : " + target,
        "Date     : " + now,
        "Secrets  : " + str(len(ss)) + "  (Critical:" + str(crit) + "  High:" + str(high) + "  Medium:" + str(med) + ")",
        "URLs     : " + str(len(set(all_urls))),
        "Files    : " + str(len(set(interesting))),
    ]
    (dirs["root"] / "summary.txt").write_text("\n".join(summary), encoding="utf-8")
    return summary, len(ss)


# --- TELEGRAM -----------------------------------------------------------------


def tg_ok():
    return (BOT_TOKEN not in ("YOUR_BOT_TOKEN_HERE", "DISABLED", "")
            and CHAT_ID not in ("YOUR_CHAT_ID_HERE", "DISABLED", ""))


def tg_msg(text):
    if not tg_ok():
        return
    try:
        requests.post(
            "https://api.telegram.org/bot" + BOT_TOKEN + "/sendMessage",
            json={
                "chat_id": CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=15,
        )
    except Exception:
        pass


def tg_file(path, caption=""):
    if not tg_ok() or not path.exists() or path.stat().st_size == 0:
        return
    try:
        with open(path, "rb") as f:
            requests.post(
                "https://api.telegram.org/bot" + BOT_TOKEN + "/sendDocument",
                data={"chat_id": CHAT_ID, "caption": caption[:1024]},
                files={"document": (path.name, f)},
                timeout=60,
            )
    except Exception:
        pass


def notify(target, secrets, files_count, dirs):
    if not tg_ok():
        return
    total = len(secrets)
    label = "[!] SECRETS FOUND" if total else "[OK] Clean"
    tg_msg(
        "<b>" + label + ": " + target + "</b>\n"
        "Files: " + str(files_count) + " | Secrets: " + str(total) + "\n"
        + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    if not secrets:
        return
    ss = sorted(secrets, key=lambda x: SEV_ORDER.get(x.get("severity", "Low"), 3))
    for s in ss[:30]:
        tg_msg(
            "<b>[" + s["severity"] + "] " + s["type"] + "</b>\n"
            "<code>" + s["type"] + ": " + s["value"] + "</code>\n"
            "Source: <code>" + s["source_url"] + "</code>\n"
            "Line: " + str(s["line"])
        )
        time.sleep(0.4)
    time.sleep(1)
    tg_file(dirs["findings"] / "secrets.js", "secrets.js - " + target)


# --- MAIN PIPELINE ------------------------------------------------------------


def scan_target(target, output_dir, threads=50, deep=False):
    target = target.strip().lower()
    if not target:
        return {}
    console.rule("[bold cyan]" + target + "[/bold cyan]")
    dirs        = setup_dirs(output_dir, target)
    raw_urls    = collect_urls(target, deep=deep)
    interesting = filter_urls(raw_urls)
    log.info("  " + str(len(interesting)) + " files to download")
    random_delay()
    downloaded, url_map = download_all(
        interesting, dirs["downloads"], workers=min(threads, 30)
    )
    random_delay()
    if downloaded:
        secrets = scan_all(downloaded, url_map, workers=min(30, max(1, len(downloaded))))
    else:
        secrets = []
    summary, count = save_results(
        dirs, target, list(raw_urls), interesting, secrets
    )
    cleanup_dl(dirs)
    tbl = Table(title="Results: " + target, header_style="bold magenta")
    tbl.add_column("Metric", style="cyan")
    tbl.add_column("Value",  style="green")
    for line in summary:
        if ":" in line:
            k, v = line.split(":", 1)
            tbl.add_row(k.strip(), v.strip())
    console.print(tbl)
    if secrets:
        console.print("\n[bold yellow]Secrets found:[/bold yellow]")
        for s in sorted(secrets, key=lambda x: SEV_ORDER.get(x.get("severity", "Low"), 3)):
            col = SEV_COLOR.get(s["severity"], "white")
            console.print("  [" + col + "]" + s["type"] + ": " + s["value"] + "[/" + col + "]")
            console.print("    Source: " + s["source_url"])
    notify(target, secrets, len(downloaded), dirs)
    log.info("[bold green]Done: " + target + " -- " + str(count) + " secrets[/bold green]\n")
    return {"target": target, "secrets": count, "files": len(downloaded)}


def parse_args():
    p = argparse.ArgumentParser(description="SecretsHunter v4.2")
    p.add_argument("-t", "--targets", default="targets.txt")
    p.add_argument("-o", "--output",  default="results/")
    p.add_argument("--threads",     type=int,   default=50)
    p.add_argument("--deep",        action="store_true")
    p.add_argument("--delay",       type=float, default=1.0)
    p.add_argument("--no-telegram", action="store_true")
    p.add_argument("--single",      type=str,   default=None)
    return p.parse_args()


def main():
    banner()
    args = parse_args()
    global BOT_TOKEN, CHAT_ID
    if args.no_telegram:
        BOT_TOKEN = CHAT_ID = "DISABLED"
    if args.single:
        targets = [args.single.strip()]
    else:
        tf = Path(args.targets)
        if not tf.exists():
            console.print("[red]Error: " + repr(args.targets) + " not found![/red]")
            sys.exit(1)
        with open(tf, encoding="utf-8", errors="replace") as f:
            targets = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not targets:
        console.print("[red]No targets![/red]")
        sys.exit(1)
    console.print(Panel(
        "Targets: " + str(len(targets)) + " | Output: " + args.output + "\n"
        "Threads: " + str(args.threads) + " | Deep: " + ("Yes" if args.deep else "No") + "\n"
        "Telegram: " + ("Off" if args.no_telegram else "On"),
        title="[bold green]Config[/bold green]",
        border_style="blue",
    ))
    all_results = []
    t0 = time.time()
    for i, tgt in enumerate(targets, 1):
        console.print("\n[bold white]Progress: " + str(i) + "/" + str(len(targets)) + "[/bold white]")
        try:
            r = scan_target(tgt, args.output, args.threads, args.deep)
            if r:
                all_results.append(r)
        except KeyboardInterrupt:
            console.print("\n[bold red]Stopped![/bold red]")
            break
        except Exception as e:
            log.error("Error " + tgt + ": " + str(e))
            all_results.append({"target": tgt, "secrets": 0, "files": 0})
        if i < len(targets):
            time.sleep(args.delay + random.uniform(0, 0.5))
    elapsed = time.time() - t0
    ts = sum(r.get("secrets", 0) for r in all_results)
    tf = sum(r.get("files",   0) for r in all_results)
    tbl = Table(title="Summary", header_style="bold cyan")
    tbl.add_column("Target",  style="white")
    tbl.add_column("Secrets", style="red")
    tbl.add_column("Files",   style="green")
    for r in all_results:
        tbl.add_row(r["target"], str(r["secrets"]), str(r["files"]))
    console.print(tbl)
    console.print(
        "\n[bold green]Done! " + str(round(elapsed, 1)) + "s | "
        "Targets: " + str(len(all_results)) + " | "
        "Secrets: " + str(ts) + " | "
        "Files: " + str(tf) + "[/bold green]"
    )
    if ts > 0:
        tg_msg(
            "Done! Targets:" + str(len(all_results))
            + " Secrets:" + str(ts)
            + " Files:" + str(tf)
            + " Time:" + str(round(elapsed)) + "s"
        )


if __name__ == "__main__":
    main()