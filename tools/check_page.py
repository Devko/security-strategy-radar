"""Integrity checks for index.html — run before every published edition.

    python tools/check_page.py            # structural checks only
    python tools/check_page.py --links    # also HTTP-check every reference URL

Exit code 0 = safe to publish, 1 = blocking findings (see should_block), 2 = crash.
The monthly scheduled run refuses to push to main unless this exits 0.
"""
import argparse, collections, concurrent.futures, re, sys, urllib.error, urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path

PAGE = Path(__file__).resolve().parent.parent / "index.html"
# References left uncited by earlier editions' in-place rewrites (as of v1.2.1).
# Do not add to this set — keep new references cited instead.
KNOWN_ORPHANS = {"r6", "r9", "r60", "r74", "r78", "r86"}
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"


@dataclass
class Finding:
    kind: str   # e.g. "anchor", "orphan", "link-broken" — see the checks below
    msg: str


def line_of(src, pos):
    return src.count("\n", 0, pos) + 1


def check_references(src, out):
    refs = {}
    for m in re.finditer(r'<li id="r(\d+)"><span class="r-org">(.*?)</span> \((.*?)\)\.(.*?)<a href="(.*?)"', src):
        refs[int(m.group(1))] = dict(org=m.group(2), date=m.group(3), url=m.group(5))
    if not refs:
        out.append(Finding("refs", "no references parsed — has the reference markup changed?"))
        return refs
    for n in sorted(set(range(1, max(refs) + 1)) - set(refs)):
        out.append(Finding("refs", f"gap in reference numbering: r{n} missing"))

    cited = collections.Counter()
    for m in re.finditer(r'<a href="#r(\d+)" title="([^"]*)">(\d+)</a>', src):
        n, title, shown, ln = int(m.group(1)), m.group(2), int(m.group(3)), line_of(src, m.start())
        cited[n] += 1
        if n != shown:
            out.append(Finding("cite", f"line {ln}: link #r{n} is displayed as [{shown}]"))
        if n not in refs:
            out.append(Finding("cite", f"line {ln}: [{n}] points to a reference that does not exist"))
        elif title.rsplit(", ", 1)[-1] != refs[n]["date"]:
            # org names may be abbreviated in tooltips; the date must match exactly
            out.append(Finding("tooltip", f"line {ln}: [{n}] tooltip date '{title}' vs reference date '{refs[n]['date']}'"))
    for n in sorted(refs):
        if not cited[n]:
            out.append(Finding("orphan", f"r{n} is never cited ({refs[n]['org']}, {refs[n]['date']})"))

    for m in re.finditer(r'<sup class="cite">\[(.*?)\]</sup>', src):
        ns = [int(x) for x in re.findall(r'href="#r(\d+)"', m.group(1))]
        if ns != sorted(set(ns)):
            out.append(Finding("order", f"line {line_of(src, m.start())}: citation group not ascending/unique {ns}"))

    by_url = collections.defaultdict(list)
    for n, r in refs.items():
        by_url[r["url"]].append(n)
    for url, ns in by_url.items():
        if len(ns) > 1:
            out.append(Finding("dup-url", f"r{', r'.join(map(str, ns))} share {url}"))
    return refs


def check_anchors(src, out):
    ids = re.findall(r'\bid="([^"]+)"', src)
    for i, c in collections.Counter(ids).items():
        if c > 1:
            out.append(Finding("id", f"duplicate id '{i}' ({c}x)"))
    for a in sorted(set(re.findall(r'href="#([^"]+)"', src)) - set(ids)):
        out.append(Finding("anchor", f"href #{a} has no target"))


class _Balance(HTMLParser):
    VOID = {"meta", "br", "img", "hr", "input", "link", "wbr"}
    IMPLICIT = {"td": {"td", "th"}, "th": {"td", "th"}, "tr": {"td", "th", "tr"}, "li": {"li"}}

    def __init__(self, out):
        super().__init__()
        self.stack, self.out = [], out

    def handle_starttag(self, tag, attrs):
        if tag in self.VOID:
            return
        while self.stack and self.stack[-1][0] in self.IMPLICIT.get(tag, ()):
            self.stack.pop()
        self.stack.append((tag, self.getpos()[0]))

    def handle_endtag(self, tag):
        if tag in self.VOID:
            return
        while self.stack and self.stack[-1][0] != tag and self.stack[-1][0] in ("td", "th", "tr", "li"):
            self.stack.pop()
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()
        else:
            top = self.stack[-1] if self.stack else ("nothing", "-")
            self.out.append(Finding("tags", f"line {self.getpos()[0]}: </{tag}> closes <{top[0]}> opened on line {top[1]}"))


def check_tags(src, out):
    p = _Balance(out)
    p.feed(src)
    for tag, ln in p.stack:
        out.append(Finding("tags", f"<{tag}> opened on line {ln} is never closed"))


def check_versions(src, out):
    patterns = {
        "header comment": r"Version: ([\d.]+)",
        "badge": r'class="vbadge">v([\d.]+)<',
        "footer": r"Security Strategy Radar v([\d.]+) ·",
        "changelog top": r"<strong>v([\d.]+) —",
    }
    found = {k: (m.group(1) if (m := re.search(p, src)) else None) for k, p in patterns.items()}
    if len(set(found.values())) != 1 or None in found.values():
        out.append(Finding("version", f"version markers disagree: {found}"))


def check_scorecard(src, out):
    rows = {p: b for p, b in re.findall(r'<tr><td>(P\d+)</td>.*?<span class="badge (\w+)">', src)}
    label = {"good": "Hit", "warn": "Partial", "crit": "Miss", "open": "Open"}
    actual = {p: label.get(b, b) for p, b in rows.items()}
    m = re.search(r'grading: <strong>(.*?)</strong>', src)
    if not m:
        out.append(Finding("scorecard", "could not find the 'grading: <strong>…</strong>' summary"))
        return
    claimed = {}
    for ids, status in re.findall(r'((?:P\d+(?:,\s*|\s+and\s+)?)+)\s+(Hit|Partial|Miss|Open)', m.group(1)):
        for p in re.findall(r"P\d+", ids):
            claimed[p] = status
    for p in sorted(set(actual) | set(claimed), key=lambda s: int(s[1:])):
        if actual.get(p) != claimed.get(p):
            out.append(Finding("scorecard", f"{p}: summary says {claimed.get(p)}, table badge says {actual.get(p)}"))


def check_charts(src, out):
    bars = re.findall(r'style="width:(\d+)%"></div></div><div class="bval">(\d+)</div>', src)
    if bars:
        top = max(int(v) for _, v in bars)
        for w, v in bars:
            if abs(round(int(v) / top * 100) - int(w)) > 1:
                out.append(Finding("chart", f"bar value {v}: width {w}% should be ~{round(int(v) / top * 100)}%"))
    cols = re.findall(r'<div class="col-v">(\d+)</div><div class="col-bar" style="height:(\d+)px">', src)
    if cols:
        scale = int(cols[0][1]) / int(cols[0][0])
        for v, h in cols:
            if abs(int(v) * scale - int(h)) > 1.5:
                out.append(Finding("chart", f"column value {v}: height {h}px should be ~{int(v) * scale:.0f}px"))


def _status(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*"})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:  # DNS failure, TLS, timeout
        return f"unreachable ({type(e).__name__})"


def check_links(refs, out):
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        results = dict(zip(refs, pool.map(_status, (r["url"] for r in refs.values()))))
    for n, code in sorted(results.items()):
        url = refs[n]["url"]
        if code in (404, 410) or isinstance(code, str):
            out.append(Finding("link-broken", f"r{n} → {code}: {url}"))
        elif code in (202, 401, 403, 429, 503, 999):
            # usually bot protection (Gartner, OpenAI, consilium, EUR-Lex); verify in a real browser
            out.append(Finding("link-blocked", f"r{n} → {code}: {url}"))


def should_block(findings: list[Finding]) -> bool:
    """Decide whether these findings must stop an automatic push to main.

    Each push to main goes live on GitHub Pages immediately and unreviewed,
    so this is the only thing between a bad edit and the public page.

    Finding kinds this script emits:
      refs, cite, anchor, id, tags, version, scorecard, chart — structural breakage
      tooltip, order, dup-url — cosmetic / bookkeeping
      orphan       — a reference that nothing cites (v1.2 shipped with 7)
      link-broken  — 404/410/DNS failure (v1.2 shipped with 2)
      link-blocked — 403/202/429: almost always bot protection, page is fine in a browser
    """
    structural = {"refs", "cite", "anchor", "id", "tags", "version", "scorecard", "chart"}
    for f in findings:
        if f.kind in structural or f.kind == "link-broken":
            return True
        # orphans that predate v1.2.1 are tolerated; any new one blocks
        if f.kind == "orphan" and f.msg.split(" ", 1)[0] not in KNOWN_ORPHANS:
            return True
    return False  # tooltip, order, dup-url, link-blocked: report only


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--links", action="store_true", help="HTTP-check every reference URL (~30 s)")
    ap.add_argument("--page", type=Path, default=PAGE)
    args = ap.parse_args()

    src = args.page.read_text(encoding="utf-8")
    findings: list[Finding] = []
    refs = check_references(src, findings)
    check_anchors(src, findings)
    check_tags(src, findings)
    check_versions(src, findings)
    check_scorecard(src, findings)
    check_charts(src, findings)
    if args.links:
        check_links(refs, findings)

    by_kind = collections.defaultdict(list)
    for f in findings:
        by_kind[f.kind].append(f.msg)
    for kind, msgs in by_kind.items():
        print(f"\n[{kind}] {len(msgs)}")
        for msg in msgs:
            print(f"  {msg}")
    print(f"\n{len(refs)} references, {len(findings)} findings")

    blocked = should_block(findings)
    print("PUBLISH GATE:", "BLOCKED" if blocked else "OK")
    return 1 if blocked else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"check_page.py crashed: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(2)
