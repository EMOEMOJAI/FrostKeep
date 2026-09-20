#!/usr/bin/env python3
"""Check public documentation links offline; never fetch external URLs."""
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = 'https://github.com/EMOEMOJAI/FrostKeep'


def prose(text):
    """Ignore fenced examples, including examples of invalid links."""
    lines, fence = [], None
    for line in text.splitlines():
        match = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if match:
            marker = match.group(1)
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and len(marker) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return '\n'.join(lines)


class HTMLLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.anchors = [], set()

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if value is None:
                continue
            if key == 'id' or (tag == 'a' and key == 'name'):
                self.anchors.add(value)
            if (tag == 'a' and key == 'href') or (tag == 'img' and key == 'src'):
                self.links.append(value)


def anchors(text):
    text = prose(text)
    html = HTMLLinks()
    html.feed(text)
    result, seen = html.anchors, Counter()
    for title in re.findall(r'^ {0,3}#{1,6}\s+(.+?)\s*#*$', text, re.M):
        title = re.sub(r'\[([^]]+)\]\([^)]*\)', r'\1', title)
        slug = re.sub(r'[^\w\- ]', '', title.lower()).replace(' ', '-')
        candidate = slug
        while candidate in result:
            seen[slug] += 1
            candidate = f'{slug}-{seen[slug]}'
        result.add(candidate)
    return result


def check(root=ROOT):
    root = root.resolve()
    public = {Path(p) for p in (root / 'RELEASE_FILES').read_text().splitlines()
              if p and not p.startswith('#')}
    failures, count = [], 0
    for relative in sorted(public):
        if relative.suffix != '.md' and relative.name != 'llms.txt':
            continue
        text = prose((root / relative).read_text())
        html = HTMLLinks()
        html.feed(text)
        links = re.findall(r'\]\(<?([^\s)>]+)>?(?:\s+"[^"]*")?\)', text)
        # Reference-style links: [label][ref] with a matching [ref]: target.
        links += re.findall(r'^\s*\[[^]]+\]:\s*<?([^\s>]+)>?', text, re.M)
        for link in links + html.links:
            base = root / relative.parent
            for prefix in (REPOSITORY + '/blob/main/', REPOSITORY + '/tree/main/'):
                if link.startswith(prefix):
                    link, base = link[len(prefix):], root
                    break
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            target = (base / unquote(url.path)).resolve() if url.path else root / relative
            try:
                destination = target.relative_to(root)
            except ValueError:
                failures.append(f'{relative}: link escapes the public repository')
                continue
            count += 1
            if destination not in public or not target.is_file():
                failures.append(f'{relative}: missing or non-public target: {link}')
            elif url.fragment and target.suffix in ('.md', '.txt'):
                if unquote(url.fragment) not in anchors(target.read_text()):
                    failures.append(f'{relative}: missing heading: {link}')
    return count, failures


if __name__ == '__main__':
    checked, errors = check()
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        raise SystemExit(1)
    print(f'Documentation checks passed: {checked} internal links and images.')
