import os
from urllib.parse import urlparse
import glob
import re
import tldextract

JPCERT_GITHUB_REPO = "https://github.com/JPCERTCC/phishurl-list.git"
OUTPUT_FILE = "pihole_blocklist.txt"
JPCERT_LOCAL_REPO_PATH = "phishurl-list"

# Whitelist Configuration
# Domains in this set will NOT be added to the generated blocklist.
WHITELIST_ROOT_DOMAINS = {
    "google.com",
    "googleapis.com",
    "github.com",
    "githubusercontent.com",
    "microsoft.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "amazonaws.com",
    "cloudflare.com",
    "sakura.ne.jp",
    "line.me",
    "yahoo.co.jp",
    "rakuten.co.jp",
}

def is_valid_domain(domain):
    """Checks if a string is a valid-looking domain name."""
    if not domain:
        return False
    if not re.match(r"^[a-zA-Z0-9-._]+$", domain):
        return False
    if '.' not in domain or domain.endswith('.'):
        return False
    for label in domain.split('.'):
        if not label or len(label) > 63:
            return False
        if label.startswith('-') or label.endswith('-'):
            return False
        if all(c == '-' for c in label):
            return False
    if len(domain) > 253:
        return False
    return True

def get_root_domain(domain):
    """Extracts the root domain using tldextract."""
    try:
        extracted = tldextract.extract(domain)
        if extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
        else:
            return extracted.domain
    except Exception:
        return None

def update_jpcert_repo():
    """Clones or pulls the JPCERT/CC phishurl-list repository."""
    if os.path.exists(JPCERT_LOCAL_REPO_PATH):
        print(f"Updating {JPCERT_LOCAL_REPO_PATH}...")
        os.system(f"cd {JPCERT_LOCAL_REPO_PATH} && git pull")
    else:
        print(f"Cloning {JPCERT_LOCAL_REPO_PATH}...")
        os.system(f"git clone {JPCERT_GITHUB_REPO} {JPCERT_LOCAL_REPO_PATH}")

def generate_blocklist():
    """Generates the Pi-hole blocklist from JPCERT/CC data."""
    domains = set()
    csv_files = glob.glob(os.path.join(JPCERT_LOCAL_REPO_PATH, '**', '*.csv'), recursive=True)
    print(f"Found {len(csv_files)} CSV files.")

    for csv_file in csv_files:
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        url = parts[1].strip()
                        if url.startswith("http://") or url.startswith("https://"):
                            try:
                                parsed_url = urlparse(url)
                                domain = parsed_url.hostname
                                if domain:
                                    domain_lower = domain.lower()
                                    root_domain = get_root_domain(domain_lower)
                                    if domain_lower in WHITELIST_ROOT_DOMAINS or \
                                       (root_domain and root_domain in WHITELIST_ROOT_DOMAINS):
                                        continue
                                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_lower):
                                        continue
                                    if is_valid_domain(domain_lower):
                                        domains.add(domain_lower)
                            except Exception:
                                continue
        except Exception as e:
            print(f"Error processing file {csv_file}: {e}")

    sorted_domains = sorted(list(domains))
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for domain in sorted_domains:
            f.write(f"0.0.0.0 {domain}\n")
    print(f"Generated {len(sorted_domains)} unique domains to {OUTPUT_FILE}")
    return True

if __name__ == "__main__":
    update_jpcert_repo()
    if generate_blocklist():
        print("Script finished: Blocklist generated successfully.")
    else:
        print("Script finished: Blocklist generation failed.")
