#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AdvancedJS_SecretsHunter.py v3.0 FIXED
Bug Bounty JS Secret Scanner — No multiprocessing, no pickle issues

INSTALL:
  go install github.com/tomnomnom/waybackurls@latest
  go install github.com/lc/gau/v2/cmd/gau@latest
  go install github.com/bp0lr/gauplus@latest
  go install github.com/projectdiscovery/katana/cmd/katana@latest
  go install github.com/hakluke/hakrawler@latest
  pip install requests rich tqdm waymore
  export PATH=$PATH:$(go env GOPATH)/bin

RUN:
  python3 AdvancedJS_SecretsHunter.py -t targets.txt -o results/ --threads 50
  python3 AdvancedJS_SecretsHunter.py --single example.com
"""

import os, re, sys, json, math, time, random, hashlib, logging, argparse, shutil, subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Tuple, Optional

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
    print(f"[!] Missing: {e}\nRun: pip install requests rich tqdm")
    sys.exit(1)

BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
CHAT_ID   = "YOUR_CHAT_ID_HERE"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]

HIGH_VALUE_EXTENSIONS = {
    '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx',
    '.json', '.env', '.map',
    '.bak', '.old', '.backup', '.tmp',
    '.config', '.yml', '.yaml', '.properties',
    '.ini', '.xml', '.log', '.txt',
}

HIGH_VALUE_PATHS = [
    "/api/",
    "/config/",
    "/secrets/",
    "/admin/",
    "/private/",
    "/internal/",
    "/debug/",
    "/test/",
    "/dev/",
    "/staging/",
    "/env/",
    "/settings/",
    "/setup/",
    "/install/",
    "/backup/",
    "/.env",
    "/wp-config",
    "/config.php",
    "/database",
    "/credentials",
    "/auth/",
    "/oauth/",
    "/token/",
]

SECRETS_PATTERNS: Dict[str, Tuple[str, str]] = {
    'OpenAI API Key': (r'sk-[a-zA-Z0-9]{20,60}T3BlbkFJ[a-zA-Z0-9]{20,60}|sk-proj-[a-zA-Z0-9\\-_]{40,100}', 'Critical'),
    'Anthropic Claude Key': (r'sk-ant-api\\d{2}-[a-zA-Z0-9\\-_]{80,110}', 'Critical'),
    'Grok xAI Key': (r'xai-[a-zA-Z0-9]{40,80}', 'Critical'),
    'Google Gemini Key': (r'AIza[0-9A-Za-z\\-_]{35}', 'Critical'),
    'HuggingFace Token': (r'hf_[a-zA-Z0-9]{30,50}', 'High'),
    'Replicate Key': (r'r8_[a-zA-Z0-9]{30,50}', 'High'),
    'AWS Access Key ID': (r'(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}', 'Critical'),
    'AWS Secret Key': (r'(?i)aws.{0,20}(?:secret|key).{0,10}["\\\']([A-Za-z0-9/+=]{40})["\\\']', 'Critical'),
    'AWS Session Token': (r'(?i)aws.session.token.{0,10}["\\\']([A-Za-z0-9/+=]{100,})["\\\']', 'Critical'),
    'AWS MWS Key': (r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'Critical'),
    'Google OAuth Secret': (r'GOCSPX-[a-zA-Z0-9\\-_]{28}', 'Critical'),
    'Google Service Account': (r'"type":\\s*"service_account"', 'Critical'),
    'Firebase API Key': (r'(?i)firebase[^\\s]*\\s*=\\s*["\\\']AIza[0-9A-Za-z\\-_]{35}["\\\']', 'Critical'),
    'Firebase Config': (r'firebaseConfig\\s*=\\s*\\{[^}]*apiKey[^}]*\\}', 'High'),
    'Azure Storage Key': (r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88};', 'Critical'),
    'Azure Client Secret': (r'(?i)azure.{0,20}(?:client.secret|password).{0,10}["\\\']([A-Za-z0-9\\-_.~]{34,})["\\\']', 'Critical'),
    'GitHub PAT Classic': (r'ghp_[a-zA-Z0-9]{36}', 'Critical'),
    'GitHub OAuth Token': (r'gho_[a-zA-Z0-9]{36}', 'Critical'),
    'GitHub App Token': (r'(?:ghu|ghs)_[a-zA-Z0-9]{36}', 'Critical'),
    'GitHub Fine-Grained PAT': (r'github_pat_[a-zA-Z0-9_]{82}', 'Critical'),
    'Stripe Secret Key': (r'sk_live_[0-9a-zA-Z]{24,}', 'Critical'),
    'Stripe Test Key': (r'sk_test_[0-9a-zA-Z]{24,}', 'High'),
    'Stripe Publishable Key': (r'pk_live_[0-9a-zA-Z]{24,}', 'Medium'),
    'Stripe Webhook Secret': (r'whsec_[a-zA-Z0-9]{32,}', 'High'),
    'Stripe Restricted Key': (r'rk_live_[0-9a-zA-Z]{24,}', 'Critical'),
    'Braintree Access Token': (r'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}', 'Critical'),
    'Slack Bot Token': (r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}', 'Critical'),
    'Slack User Token': (r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}', 'Critical'),
    'Slack Webhook URL': (r'https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,11}/[a-zA-Z0-9_]{24}', 'High'),
    'Slack App Token': (r'xapp-\\d-[A-Z0-9]+-\\d+-[a-f0-9]+', 'Critical'),
    'Twilio Account SID': (r'AC[a-f0-9]{32}', 'High'),
    'Twilio Auth Token': (r'(?i)twilio.{0,20}(?:auth.token|authtoken).{0,10}["\\\']([a-f0-9]{32})["\\\']', 'Critical'),
    'SendGrid API Key': (r'SG\\.[a-zA-Z0-9\\-_]{22}\\.[a-zA-Z0-9\\-_]{43}', 'Critical'),
    'Mailgun API Key': (r'key-[0-9a-zA-Z]{32}', 'Critical'),
    'JSON Web Token': (r'eyJ[a-zA-Z0-9\\-_=]+\\.eyJ[a-zA-Z0-9\\-_=]+\\.[a-zA-Z0-9\\-_.+/=]*', 'High'),
    'JWT Secret': (r'(?i)jwt.{0,20}(?:secret|key).{0,10}["\\\']([a-zA-Z0-9\\-_.~!@#$%^&*]{20,})["\\\']', 'Critical'),
    'MongoDB URI': (r'mongodb(?:\\+srv)?://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&()*+,;=%]{10,}', 'Critical'),
    'PostgreSQL URI': (r'postgres(?:ql)?://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&()*+,;=%]{10,}', 'Critical'),
    'MySQL URI': (r'mysql://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&()*+,;=%]{10,}', 'Critical'),
    'Redis URL': (r'redis://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&()*+,;=%]{10,}', 'High'),
    'Database Password': (r'(?i)(?:db|database)[\\s_-]*(?:pass(?:word)?|pwd)\\s*[=:]\\s*["\\\']([^"\\\']{8,})["\\\']', 'Critical'),
    'RSA Private Key': (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'Critical'),
    'PGP Private Key': (r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'Critical'),
    'Supabase Service Key': (r'(?i)supabase.{0,20}service.role.{0,10}["\\\']([a-zA-Z0-9._\\-]{100,})["\\\']', 'Critical'),
    'Supabase Anon Key': (r'(?i)supabase.{0,20}anon.{0,10}["\\\']([a-zA-Z0-9._\\-]{100,})["\\\']', 'High'),
    'Supabase Env Var': (r'SUPABASE_(?:URL|ANON_KEY|SERVICE_ROLE_KEY)\\s*=\\s*["\\\']([^"\\\']+)["\\\']', 'High'),
    'DigitalOcean Token': (r'dop_v1_[a-f0-9]{64}', 'Critical'),
    'Cloudflare API Token': (r'(?i)cloudflare.{0,10}(?:api.token|auth.key).{0,10}["\\\']([a-zA-Z0-9\\-_]{40})["\\\']', 'Critical'),
    'Vercel Token': (r'(?i)vercel.{0,10}token.{0,10}["\\\']([a-zA-Z0-9\\-_]{24,})["\\\']', 'High'),
    'Heroku API Key': (r'(?i)heroku.{0,10}(?:api.key|token).{0,10}["\\\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\\\']', 'Critical'),
    'HashiCorp Vault Token': (r's\\.[a-zA-Z0-9]{24}', 'Critical'),
    'NPM Token': (r'npm_[a-zA-Z0-9]{36}', 'High'),
    'NPM Auth Token': (r'//registry\\.npmjs\\.org/:_authToken\\s*=\\s*([a-zA-Z0-9\\-_]{36,})', 'High'),
    'Shopify Access Token': (r'shpat_[a-fA-F0-9]{32}', 'Critical'),
    'Shopify Storefront Token': (r'shpss_[a-fA-F0-9]{32}', 'High'),
    'Discord Webhook': (r'https://discord(?:app)?\\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_\\-]{60,}', 'Medium'),
    'Telegram Bot Token': (r'\\d{8,10}:[a-zA-Z0-9_\\-]{35}', 'High'),
    'Sentry DSN': (r'https://[a-f0-9]{32}@[a-z0-9]+\\.ingest\\.sentry\\.io/[0-9]+', 'Medium'),
    'Datadog API Key': (r'(?i)datadog.{0,10}(?:api.key|app.key).{0,10}["\\\']([a-f0-9]{32,40})["\\\']', 'High'),
    'Mapbox Token': (r'pk\\.[a-zA-Z0-9]{60,}\\.[a-zA-Z0-9\\-_]{22}', 'Medium'),
    'Algolia Admin Key': (r'(?i)algolia.{0,10}(?:admin.api.key|api.key).{0,10}["\\\']([a-f0-9]{32})["\\\']', 'High'),
    'Generic Password': (r'(?i)(?:password|passwd|pass|pwd)\\s*[=:]\\s*["\\\']([^"\\\']{8,})["\\\']', 'High'),
    'Generic Secret Key': (r'(?i)(?:secret.key|secret_key|secretkey)\\s*[=:]\\s*["\\\']([^"\\\']{16,})["\\\']', 'High'),
    'Generic API Key': (r'(?i)(?:api.key|api_key|apikey)\\s*[=:]\\s*["\\\']([^"\\\']{16,})["\\\']', 'Medium'),
    'Bearer Token': (r'(?i)Authorization["\\\']?\\s*:\\s*["\\\']?Bearer\\s+([a-zA-Z0-9\\-_=.+/]{20,})', 'High'),
    'Basic Auth': (r'(?i)Authorization["\\\']?\\s*:\\s*["\\\']?Basic\\s+([a-zA-Z0-9+/=]{20,})', 'High'),
    'SMTP Credentials': (r'(?i)smtp.{0,10}(?:user|pass(?:word)?|auth).{0,10}["\\\']([^"\\\']{6,})["\\\']', 'High'),
    'Internal IP': (r'(?:10\\.|172\\.(?:1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)\\d{1,3}\\.\\d{1,3}(?::\\d+)?', 'Medium'),
    'WordPress Secret Key': (r"define\\s*\\(\\s*'[A-Z_]*(?:SECRET|KEY|SALT)[A-Z_]*'\\s*,\\s*'([^']{30,})'", 'High'),
    'Source Map Ref': (r'//# sourceMappingURL=([^\\s]+\\.map)', 'Medium'),
    'Ethereum Private Key': (r'(?i)(?:private.key|secret)\\s*[=:]\\s*["\\\']?(0x[a-fA-F0-9]{64})["\\\']?', 'Critical'),
    'Infura Project ID': (r'infura\\.io/v3/([a-f0-9]{32})', 'High'),
    'Notion Token': (r'secret_[a-zA-Z0-9]{43}', 'High'),
    'Linear API Key': (r'lin_api_[a-zA-Z0-9]{40}', 'High'),
    'Airtable Key': (r'(?:key|pat)[a-zA-Z0-9]{14}\\.[a-f0-9]{64}', 'High'),
}

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_EMOJI = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢", "Info": "ℹ️"}


console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[
        RichHandler(rich_tracebacks=True, console=console),
        logging.FileHandler("hunter.log", encoding="utf-8"),
    ]
)
log = logging.getLogger("SecretsHunter")


def banner():
    console.print(Panel.fit(
        "[bold cyan]AdvancedJS SecretsHunter[/bold cyan] [bold yellow]v3.0 FIXED[/bold yellow]\n"
        "[dim]Bug Bounty & Authorized Penetration Testing Only[/dim]",
        title="[bold green]🔍 Secrets Hunter[/bold green]",
        border_style="bright_blue"
    ))

def random_ua():
    return random.choice(USER_AGENTS)

def random_delay(mn=0.3, mx=1.5):
    time.sleep(random.uniform(mn, mx))

def mask_secret(value):
    value = value.strip()
    if len(value) <= 10:
        return "*" * len(value)
    return value[:6] + "*" * (len(value) - 10) + value[-4:]

def shannon_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)

def is_tool_installed(tool):
    try:
        r = subprocess.run(["which", tool], capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False

def create_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1.0, status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET", "HEAD"])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": random_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
    })
    return session

def setup_dirs(base, target):
    root = Path(base) / target
    dirs = {"root": root, "downloads": root / "downloaded_files", "findings": root / "findings"}
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs

def cleanup_downloads(dirs):
    dl = dirs.get("downloads")
    if dl and dl.exists():
        try:
            shutil.rmtree(dl)
            log.info("  [trash] downloaded_files/ deleted - disk space freed")
        except Exception as e:
            log.warning(f"  [cleanup] {e}")


# PHASE 1 - URL COLLECTION

def run_cmd(cmd, timeout=120):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        if result.stdout:
            return [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except subprocess.TimeoutExpired:
        log.debug(f"[timeout] {cmd[0]}")
    except FileNotFoundError:
        log.debug(f"[not found] {cmd[0]}")
    except Exception as e:
        log.debug(f"[error] {cmd[0]}: {e}")
    return []

def collect_urls(domain, deep=False):
    log.info(f"[bold blue]Collecting URLs for: {domain}[/bold blue]")
    commands = []
    if is_tool_installed("waybackurls"):
        commands.append(["waybackurls", domain])
    if is_tool_installed("gau"):
        commands.append(["gau", "--subs", "--providers=all", domain])
    if is_tool_installed("gauplus"):
        commands.append(["gauplus", "-t", "5", domain])
    if is_tool_installed("katana"):
        commands.append(["katana", "-u", f"https://{domain}", "-jc", "-d", "3", "-silent"])
    if is_tool_installed("hakrawler"):
        commands.append(["hakrawler", "-subs", "-u", f"https://{domain}"])
    if is_tool_installed("getJS"):
        commands.append(["getJS", "--url", f"https://{domain}", "--complete"])
    if deep and is_tool_installed("waymore"):
        commands.append(["waymore", "-i", domain, "-mode", "U"])
    if not commands:
        log.warning("No recon tools found - using basic crawl")
        return basic_crawl(domain)
    all_urls = set()
    with ThreadPoolExecutor(max_workers=len(commands)) as ex:
        futs = {ex.submit(run_cmd, cmd): cmd[0] for cmd in commands}
        for fut in as_completed(futs):
            tool = futs[fut]
            try:
                urls = fut.result()
                log.info(f"  [{tool}] found {len(urls)} URLs")
                all_urls.update(urls)
            except Exception as e:
                log.debug(f"  [{tool}] error: {e}")
    log.info(f"  Total unique URLs: {len(all_urls)}")
    return all_urls

def basic_crawl(domain):
    urls = set()
    session = create_session()
    for scheme in ["https", "http"]:
        try:
            r = session.get(f"{scheme}://{domain}", timeout=10)
            for m in re.finditer(r'src=["\'\']([^"\'\']+ \.js[^"\'\']* )["\'\']', r.text):
                u = m.group(1)
                urls.add(u if u.startswith("http") else f"{scheme}://{domain}/{u.lstrip('/')}")
            break
        except Exception:
            continue
    return urls

def filter_urls(urls):
    result = []
    for url in urls:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            continue
        path = urlparse(url).path.lower()
        ok = any(path.endswith(ext) or f"{ext}?" in path for ext in HIGH_VALUE_EXTENSIONS)
        if not ok:
            ok = any(p in path for p in HIGH_VALUE_PATHS)
        if ok:
            result.append(url)
    return list(set(result))


# PHASE 2 - DOWNLOADING

def download_one(url, save_dir, session):
    parsed = urlparse(url)
    safe_name = re.sub(r'[^\w\-_.]', '_', parsed.path.lstrip('/'))[-150:] or hashlib.md5(url.encode()).hexdigest()[:16]
    save_path = save_dir / safe_name
    if save_path.exists() and save_path.stat().st_size > 0:
        return (save_path, url)
    for attempt in range(3):
        try:
            session.headers["User-Agent"] = random_ua()
            r = session.get(url, timeout=10, stream=True, allow_redirects=True)
            if r.status_code == 200 and r.content:
                with open(save_path, "wb") as f:
                    for chunk in r.iter_content(8192):
                        f.write(chunk)
                return (save_path, url)
            if r.status_code in (403, 404):
                break
        except requests.RequestException:
            if attempt < 2:
                time.sleep(random.uniform(1, 2))
    try:
        r = session.get(f"https://archive.org/wayback/available?url={url}", timeout=10)
        if r.status_code == 200:
            snap = r.json().get("archived_snapshots", {}).get("closest", {})
            if snap.get("available"):
                r2 = session.get(snap["url"], timeout=15)
                if r2.status_code == 200 and r2.content:
                    with open(save_path, "wb") as f:
                        f.write(r2.content)
                    return (save_path, url)
    except Exception:
        pass
    return None

def download_all(urls, save_dir, workers=20):
    downloaded = []
    url_map = {}
    session = create_session()
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as prog:
        task = prog.add_task(f"[cyan]Downloading {len(urls)} files...", total=len(urls))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(download_one, url, save_dir, session): url for url in urls}
            for fut in as_completed(futs):
                prog.advance(task)
                try:
                    res = fut.result()
                    if res:
                        local_path, src_url = res
                        downloaded.append(local_path)
                        url_map[str(local_path)] = src_url
                except Exception as e:
                    log.debug(f"Download error: {e}")
    log.info(f"  Downloaded {len(downloaded)}/{len(urls)} files")
    return downloaded, url_map


# PHASE 3 - SCANNING
# Uses ThreadPoolExecutor ONLY - no multiprocessing, no pickle issues ever

def scan_one_file(file_path, source_url, entropy_threshold=4.7):
    findings = []
    endpoints = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return [], []

    for secret_name, (pattern, severity) in SECRETS_PATTERNS.items():
        try:
            for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
                value = match.group(0)
                try:
                    g1 = match.group(1)
                    if g1:
                        value = g1
                except IndexError:
                    pass
                value = value.strip()
                if len(value) < 8:
                    continue
                line_num = content[:match.start()].count("\n") + 1
                ctx_start = max(0, match.start() - 80)
                ctx_end = min(len(content), match.end() + 80)
                context = content[ctx_start:ctx_end].replace("\n", " ").strip()
                findings.append({
                    "file": str(file_path),
                    "source_url": source_url,
                    "type": secret_name,
                    "masked_value": mask_secret(value),
                    "severity": severity,
                    "line_number": line_num,
                    "context": context[:250],
                })
        except re.error:
            continue

    seen = set()
    for match in re.finditer(r'["\'\']([a-zA-Z0-9+/=_\-]{20,100})["\'\']', content):
        candidate = match.group(1)
        if candidate in seen:
            continue
        seen.add(candidate)
        if shannon_entropy(candidate) >= entropy_threshold:
            if any(f["masked_value"] == mask_secret(candidate) for f in findings):
                continue
            line_num = content[:match.start()].count("\n") + 1
            findings.append({
                "file": str(file_path),
                "source_url": source_url,
                "type": "High-Entropy String",
                "masked_value": mask_secret(candidate),
                "severity": "Medium",
                "line_number": line_num,
                "context": f"Entropy: {shannon_entropy(candidate):.2f}",
            })

    ep_patterns = [
        r'/(?:api|v[0-9]+|rest|graphql|gql)/[a-zA-Z0-9\-_/]+',
        r'(?:url|endpoint|path|route)\s*[=:]\s*["\'\']([^"\'\']+ )["\'\']',
        r'app\.(?:get|post|put|delete|patch)\s*\(["\'\']([^"\'\']+ )["\'\']',
        r'router\.(?:get|post|put|delete|patch)\s*\(["\'\']([^"\'\']+ )["\'\']',
    ]
    for pat in ep_patterns:
        try:
            for m in re.finditer(pat, content, re.IGNORECASE):
                ep = m.group(0)[:300].strip()
                if 3 < len(ep) < 300:
                    endpoints.append(ep)
        except re.error:
            continue

    return findings, list(set(endpoints))


def scan_all_files(file_paths, url_map, workers=30, entropy_threshold=4.7):
    log.info(f"[bold green]Scanning {len(file_paths)} files for secrets...[/bold green]")
    valid = [fp for fp in file_paths if fp.exists() and fp.stat().st_size > 0]
    if not valid:
        log.warning("  No valid files to scan")
        return [], []
    all_findings = []
    all_endpoints = []
    num_workers = min(workers, (os.cpu_count() or 4) * 2, len(valid))

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as prog:
        task = prog.add_task("[green]Scanning files...", total=len(valid))
        with ThreadPoolExecutor(max_workers=num_workers) as ex:
            future_map = {}
            for fp in valid:
                src_url = url_map.get(str(fp), "unknown")
                submitted = ex.submit(scan_one_file, fp, src_url, entropy_threshold)
                future_map[submitted] = fp
            for fut in as_completed(future_map):
                prog.advance(task)
                try:
                    file_findings, file_endpoints = fut.result()
                    all_findings.extend(file_findings)
                    all_endpoints.extend(file_endpoints)
                except Exception as e:
                    log.debug(f"Scan error {future_map[fut].name}: {e}")

    unique_endpoints = list(set(all_endpoints))
    log.info(f"  Found {len(all_findings)} secrets | {len(unique_endpoints)} endpoints")
    return all_findings, unique_endpoints


# PHASE 4 - SAVE RESULTS

def save_results(dirs, target, all_urls, interesting_urls, secrets, endpoints):
    sorted_secrets = sorted(secrets, key=lambda x: SEV_ORDER.get(x.get("severity", "Info"), 4))
    (dirs["root"] / "all_urls.txt").write_text("\n".join(sorted(set(all_urls))), encoding="utf-8")
    (dirs["root"] / "interesting_files.txt").write_text("\n".join(sorted(set(interesting_urls))), encoding="utf-8")
    with open(dirs["findings"] / "secrets.json", "w", encoding="utf-8") as f:
        json.dump({"target": target, "scan_date": datetime.now().isoformat(),
                   "total_secrets": len(secrets), "total_endpoints": len(endpoints),
                   "secrets": sorted_secrets}, f, indent=2, ensure_ascii=False)
    lines = ["=" * 55, f"  SecretsHunter: {target}",
             f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
             f"  Secrets: {len(secrets)} | Endpoints: {len(endpoints)}", "=" * 55, ""]
    for s in sorted_secrets:
        lines += [f"[{s['severity']}] {s['type']}",
                  f"  URL:     {s.get('source_url','N/A')}",
                  f"  File:    {s['file']}",
                  f"  Value:   {s['masked_value']}",
                  f"  Line:    {s.get('line_number','?')}",
                  f"  Context: {s.get('context','')[:150]}", ""]
    (dirs["findings"] / "secrets.txt").write_text("\n".join(lines), encoding="utf-8")
    (dirs["findings"] / "endpoints.txt").write_text("\n".join(sorted(set(endpoints))), encoding="utf-8")

    md = [f"# SecretsHunter: {target}",
          f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
          f"**Secrets:** {len(secrets)} | **Endpoints:** {len(set(endpoints))}",
          "\n---\n", "## Severity Summary\n", "| Severity | Count |", "|----------|-------|"]
    for sev in ["Critical", "High", "Medium", "Low"]:
        md.append(f"| {SEV_EMOJI.get(sev,'')} {sev} | {sum(1 for s in secrets if s.get('severity')==sev)} |")
    md += ["\n---\n", "## Secrets\n"]
    for i, s in enumerate(sorted_secrets, 1):
        md += [f"### {i}. {SEV_EMOJI.get(s['severity'],'')} {s['type']}",
               f"- **Severity:** {s['severity']}",
               f"- **URL:** {s.get('source_url','N/A')}",
               f"- **Value:** `{s['masked_value']}`",
               f"- **Line:** {s.get('line_number','?')}",
               f"- **Context:**", "```", s.get("context","")[:300], "```\n"]
    if endpoints:
        md += ["\n---\n", "## Endpoints\n", "```"]
        md += sorted(set(endpoints))[:200]
        md.append("```\n")
    md.append("\n*Generated by AdvancedJS_SecretsHunter v3.0*")
    (dirs["findings"] / "full_report.md").write_text("\n".join(md), encoding="utf-8")

    critical = sum(1 for s in secrets if s.get("severity") == "Critical")
    high     = sum(1 for s in secrets if s.get("severity") == "High")
    medium   = sum(1 for s in secrets if s.get("severity") == "Medium")
    summary = [
        f"Target:              {target}",
        f"Scan Date:           {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total URLs:          {len(set(all_urls))}",
        f"Interesting Files:   {len(set(interesting_urls))}",
        f"Total Secrets Found: {len(secrets)}",
        f"  - Critical:        {critical}",
        f"  - High:            {high}",
        f"  - Medium:          {medium}",
        f"Endpoints Found:     {len(set(endpoints))}",
    ]
    (dirs["root"] / "summary.txt").write_text("\n".join(summary), encoding="utf-8")
    return summary


# PHASE 5 - TELEGRAM

def _tg_ok():
    return (BOT_TOKEN not in ("YOUR_BOT_TOKEN_HERE", "DISABLED", "") and
            CHAT_ID   not in ("YOUR_CHAT_ID_HERE",  "DISABLED", ""))

def send_tg_msg(text):
    if not _tg_ok():
        return
    try:
        requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
                      json={"chat_id": CHAT_ID, "text": text, "parse_mode": "HTML",
                            "disable_web_page_preview": True}, timeout=15)
    except Exception as e:
        log.debug(f"TG msg error: {e}")

def send_tg_file(file_path, caption=""):
    if not _tg_ok() or not file_path.exists() or file_path.stat().st_size == 0:
        return
    try:
        with open(file_path, "rb") as f:
            requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
                          data={"chat_id": CHAT_ID, "caption": caption[:1024]},
                          files={"document": (file_path.name, f)}, timeout=60)
    except Exception as e:
        log.debug(f"TG file error: {e}")

def notify(target, secrets, files_count, dirs):
    if not _tg_ok():
        return
    total = len(secrets)
    send_tg_msg(
        f"{'🔴' if total else '✅'} <b>Scan: {target}</b>\n"
        f"📁 Files: {files_count}\n🔍 Secrets: {total}\n"
        f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    if not secrets:
        return
    for s in [s for s in secrets if s.get("severity") in ("Critical", "High")][:25]:
        send_tg_msg(
            f"{SEV_EMOJI.get(s.get('severity',''),'⚪')} <b>[{s.get('severity','?')}] {s.get('type','?')}</b>\n"
            f"🎯 <b>Target:</b> {target}\n"
            f"🔗 <b>URL:</b> <code>{s.get('source_url','N/A')}</code>\n"
            f"🔑 <b>Value:</b> <code>{s.get('masked_value','N/A')}</code>\n"
            f"📄 Line: {s.get('line_number','?')}"
        )
        time.sleep(0.5)
    time.sleep(1)
    send_tg_file(dirs["findings"] / "secrets.txt", f"Secrets: {target}")
    time.sleep(1)
    send_tg_file(dirs["findings"] / "full_report.md", f"Report: {target}")


# MAIN PIPELINE

def scan_target(target, output_dir, threads=50, deep=False, entropy=4.7):
    target = target.strip().lower()
    if not target:
        return {}
    console.rule(f"[bold cyan]Target: {target}[/bold cyan]")
    log.info(f"Starting scan: {target}")
    dirs = setup_dirs(output_dir, target)
    raw_urls    = collect_urls(target, deep=deep)
    interesting = filter_urls(raw_urls)
    log.info(f"  {len(interesting)} interesting files from {len(raw_urls)} URLs")
    random_delay(0.3, 1.0)
    downloaded, url_map = download_all(interesting, dirs["downloads"], workers=min(threads, 30))
    random_delay(0.2, 0.8)
    if downloaded:
        secrets, endpoints = scan_all_files(downloaded, url_map, workers=min(30, len(downloaded)), entropy_threshold=entropy)
    else:
        secrets, endpoints = [], []
        log.warning(f"  No files downloaded for {target}")
    summary = save_results(dirs, target, list(raw_urls), interesting, secrets, endpoints)
    cleanup_downloads(dirs)
    tbl = Table(title=f"Results: {target}", header_style="bold magenta")
    tbl.add_column("Metric", style="cyan")
    tbl.add_column("Value", style="green")
    for line in summary:
        if ":" in line:
            k, v = line.split(":", 1)
            tbl.add_row(k.strip(), v.strip())
    console.print(tbl)
    notify(target, secrets, len(downloaded), dirs)
    log.info(f"[bold green]Done: {target}[/bold green]\n")
    return {"target": target, "secrets": len(secrets), "files": len(downloaded), "endpoints": len(endpoints)}


def parse_args():
    p = argparse.ArgumentParser(description="AdvancedJS SecretsHunter v3.0 FIXED")
    p.add_argument("-t", "--targets",  default="targets.txt")
    p.add_argument("-o", "--output",   default="results/")
    p.add_argument("--threads",        type=int,   default=50)
    p.add_argument("--deep",           action="store_true")
    p.add_argument("--entropy",        type=float, default=4.7)
    p.add_argument("--delay",          type=float, default=1.0)
    p.add_argument("--no-telegram",    action="store_true")
    p.add_argument("--single",         type=str,   default=None)
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
            console.print(f"[red]Error: '{args.targets}' not found![/red]")
            sys.exit(1)
        with open(tf, encoding="utf-8", errors="replace") as f:
            targets = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    if not targets:
        console.print("[red]No targets![/red]")
        sys.exit(1)
    console.print(Panel(
        f"Targets: {len(targets)}\nOutput: {args.output}\nThreads: {args.threads}\n"
        f"Deep: {'Yes' if args.deep else 'No'}\nEntropy: {args.entropy}\n"
        f"Telegram: {'Disabled' if args.no_telegram else 'Enabled'}",
        title="[bold green]Scan Configuration[/bold green]", border_style="blue"
    ))
    all_results = []
    start_time = time.time()
    for i, target in enumerate(targets, 1):
        console.print(f"\n[bold white]Progress: {i}/{len(targets)}[/bold white]")
        try:
            result = scan_target(target=target, output_dir=args.output,
                                 threads=args.threads, deep=args.deep, entropy=args.entropy)
            if result:
                all_results.append(result)
        except KeyboardInterrupt:
            console.print("\n[bold red]Interrupted![/bold red]")
            break
        except Exception as e:
            log.error(f"Error scanning {target}: {e}")
            all_results.append({"target": target, "secrets": 0, "files": 0, "endpoints": 0})
        if i < len(targets):
            delay = args.delay + random.uniform(0, 1.0)
            log.info(f"Waiting {delay:.1f}s...")
            time.sleep(delay)
    elapsed = time.time() - start_time
    ts = sum(r.get("secrets", 0) for r in all_results)
    tf2 = sum(r.get("files", 0) for r in all_results)
    te = sum(r.get("endpoints", 0) for r in all_results)
    tbl = Table(title="Final Summary", header_style="bold cyan")
    tbl.add_column("Target",    style="white")
    tbl.add_column("Secrets",   style="red")
    tbl.add_column("Files",     style="green")
    tbl.add_column("Endpoints", style="yellow")
    for r in all_results:
        tbl.add_row(r["target"], str(r["secrets"]), str(r["files"]), str(r["endpoints"]))
    console.print(tbl)
    console.print(f"\n[bold green]Done! {elapsed:.1f}s | Targets: {len(all_results)} | Secrets: {ts} | Files: {tf2} | Endpoints: {te}[/bold green]")
    if ts > 0:
        send_tg_msg(f"All done!\nTargets: {len(all_results)}\nSecrets: {ts}\nFiles: {tf2}\nTime: {elapsed:.0f}s")


if __name__ == "__main__":
    main()
