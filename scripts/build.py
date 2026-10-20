#!/usr/bin/env python3
"""Build Loon rule lists for China-direct traffic from upstream sources plus local overrides."""

import ipaddress
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
CUSTOM = ROOT / "custom"

# label -> (url, format); format is "v2ray" or "dotlist", see the parse_* functions.
DOMAIN_SOURCES = {
    "Loyalsoldier/v2ray-rules-dat direct-list": (
        "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt", "v2ray"),
    "blackmatrix7 ChinaMaxNoMedia_Domain": (
        "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/ChinaMaxNoMedia/ChinaMaxNoMedia_Domain.list", "dotlist"),
}
IP_SOURCES = {
    "Loyalsoldier/geoip cn": "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/cn.txt",
}

# Guard rails, checked per source before custom entries are merged, so a truncated or
# reformatted upstream file aborts the build instead of being published.
# Each domain source has ~110k entries and the CIDR source ~10k (2026-10).
MIN_DOMAINS_PER_SOURCE = 90000
MIN_CIDRS_PER_SOURCE = 8000
MUST_COVER = ["qq.com", "weixin.qq.com", "taobao.com", "alipay.com", "dingtalk.com", "jd.com"]

DOMAIN_RE = re.compile(r"^[a-z0-9_-]+(\.[a-z0-9_-]+)*$")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "loon-cn-rules-builder"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        return resp.read().decode("utf-8-sig")


def normalize(domain):
    domain = domain.strip().lower().rstrip(".")
    return domain if DOMAIN_RE.match(domain) else None


def is_network(value, version):
    try:
        return ipaddress.ip_network(value, strict=False).version == version
    except ValueError:
        return False


def parse_v2ray(text):
    """v2ray text list: plain/domain: = suffix, full: = exact, regexp:/keyword: skipped."""
    suffixes, exacts = set(), set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("regexp:", "keyword:")):
            continue
        target = suffixes
        if line.startswith("full:"):
            target, line = exacts, line[len("full:"):]
        elif line.startswith("domain:"):
            line = line[len("domain:"):]
        domain = normalize(line.split(":@", 1)[0])
        if domain:
            target.add(domain)
    return suffixes, exacts


def parse_dotlist(text):
    """Domain-set list: '.example.com' = suffix, 'example.com' = exact."""
    suffixes, exacts = set(), set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("."):
            domain = normalize(line[1:])
            if domain:
                suffixes.add(domain)
        else:
            domain = normalize(line)
            if domain:
                exacts.add(domain)
    return suffixes, exacts


def parse_custom(text):
    """Custom list: plain domain or DOMAIN-SUFFIX = suffix, DOMAIN = exact,
    DOMAIN-KEYWORD / USER-AGENT / IP-CIDR(6) with no-resolve kept as extra rules.
    Raises ValueError listing every line that does not fit, instead of guessing."""
    suffixes, exacts, extra, errors = set(), set(), [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split(",")]
        if len(fields) == 1:
            fields = ["DOMAIN-SUFFIX", fields[0]]
        kind, value, options = fields[0].upper(), fields[1], fields[2:]
        if kind in ("DOMAIN-SUFFIX", "DOMAIN") and not options and normalize(value):
            (suffixes if kind == "DOMAIN-SUFFIX" else exacts).add(normalize(value))
        elif kind in ("DOMAIN-KEYWORD", "USER-AGENT") and value and not options:
            extra.append(f"{kind},{value}")
        elif kind in ("IP-CIDR", "IP-CIDR6") and options == ["no-resolve"] \
                and is_network(value, 4 if kind == "IP-CIDR" else 6):
            extra.append(f"{kind},{ipaddress.ip_network(value, strict=False)},no-resolve")
        else:
            errors.append(f"line {lineno}: {raw.strip()}")
    if errors:
        raise ValueError("invalid rules (no policy field allowed; IP rules must end with no-resolve):\n  "
                         + "\n  ".join(errors))
    return suffixes, exacts, extra


def parse_cidrs(text):
    nets = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            nets.append(ipaddress.ip_network(line, strict=False))
    return nets


def covering_suffix(domain, suffixes, include_self=True):
    """Return the suffix in `suffixes` that matches `domain`, or None."""
    parts = domain.split(".")
    for i in range(0 if include_self else 1, len(parts)):
        candidate = ".".join(parts[i:])
        if candidate in suffixes:
            return candidate
    return None


def apply_excludes(suffixes, exacts, excludes):
    """Drop excluded domains and everything under them."""
    def keep(d):
        return covering_suffix(d, excludes) is None
    return {d for d in suffixes if keep(d)}, {d for d in exacts if keep(d)}


def compact(suffixes, exacts):
    """Remove entries already matched by a broader suffix."""
    kept_suffixes = {d for d in suffixes if covering_suffix(d, suffixes, include_self=False) is None}
    kept_exacts = {d for d in exacts if covering_suffix(d, kept_suffixes) is None}
    return kept_suffixes, kept_exacts


def collapse(nets):
    v4 = list(ipaddress.collapse_addresses(n for n in nets if n.version == 4))
    v6 = list(ipaddress.collapse_addresses(n for n in nets if n.version == 6))
    return v4, v6


def read_custom(name):
    path = CUSTOM / name
    return path.read_text(encoding="utf-8-sig") if path.exists() else ""


def header(name, counts, sources):
    lines = [f"# NAME: {name}", "# REPO: https://github.com/kk66615/loon-cn-rules"]
    lines += [f"# {key}: {value}" for key, value in counts.items()]
    lines += [f"# SOURCE: {label} {url}" for label, url in sources]
    return lines


def build():
    errors = []
    parsers = {"v2ray": parse_v2ray, "dotlist": parse_dotlist}
    suffixes, exacts = set(), set()
    for label, (url, fmt) in DOMAIN_SOURCES.items():
        s, e = parsers[fmt](fetch(url))
        if len(s) + len(e) < MIN_DOMAINS_PER_SOURCE:
            errors.append(f"{label}: only {len(s) + len(e)} domains (< {MIN_DOMAINS_PER_SOURCE})")
        suffixes |= s
        exacts |= e
    for domain in MUST_COVER:
        if covering_suffix(domain, suffixes) is None and domain not in exacts:
            errors.append(f"upstream no longer covers required domain: {domain}")

    nets = []
    for label, url in IP_SOURCES.items():
        source_nets = parse_cidrs(fetch(url))
        if len(source_nets) < MIN_CIDRS_PER_SOURCE:
            errors.append(f"{label}: only {len(source_nets)} cidrs (< {MIN_CIDRS_PER_SOURCE})")
        nets += source_nets

    try:
        custom_suffixes, custom_exacts, extra_rules = parse_custom(read_custom("direct.list"))
        excludes, exclude_exacts, exclude_extra = parse_custom(read_custom("exclude.list"))
    except ValueError as exc:
        errors.append(f"custom list: {exc}")
    else:
        if exclude_exacts or exclude_extra:
            errors.append("exclude.list only accepts plain domains or DOMAIN-SUFFIX lines")

    if errors:
        sys.exit("build aborted:\n  " + "\n  ".join(errors))

    suffixes |= custom_suffixes
    exacts |= custom_exacts
    suffixes, exacts = apply_excludes(suffixes, exacts, excludes)
    suffixes, exacts = compact(suffixes, exacts)
    v4, v6 = collapse(nets)

    for domain in sorted(excludes):
        parent = covering_suffix(domain, suffixes)
        if parent:
            print(f"warning: excluded {domain} is still matched by DOMAIN-SUFFIX,{parent}; "
                  "add a proxy rule for it under [Rule] in Loon", file=sys.stderr)

    DIST.mkdir(exist_ok=True)
    domain_lines = header(
        "CN_Domain",
        {"DOMAIN-SUFFIX": len(suffixes), "DOMAIN": len(exacts), "CUSTOM-EXTRA": len(extra_rules)},
        [(label, url) for label, (url, _) in DOMAIN_SOURCES.items()],
    )
    domain_lines += extra_rules
    domain_lines += [f"DOMAIN-SUFFIX,{d}" for d in sorted(suffixes)]
    domain_lines += [f"DOMAIN,{d}" for d in sorted(exacts)]
    (DIST / "CN_Domain.list").write_text("\n".join(domain_lines) + "\n", encoding="utf-8")

    ip_lines = header("CN_IP", {"IP-CIDR": len(v4), "IP-CIDR6": len(v6)}, IP_SOURCES.items())
    ip_lines += [f"IP-CIDR,{n},no-resolve" for n in v4]
    ip_lines += [f"IP-CIDR6,{n},no-resolve" for n in v6]
    (DIST / "CN_IP.list").write_text("\n".join(ip_lines) + "\n", encoding="utf-8")

    print(f"CN_Domain: {len(suffixes)} suffix + {len(exacts)} exact + {len(extra_rules)} extra; "
          f"CN_IP: {len(v4)} v4 + {len(v6)} v6")


if __name__ == "__main__":
    build()
