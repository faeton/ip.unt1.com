#!/usr/bin/env python3
"""Replace the ip.unt1.com block in /etc/caddy/Caddyfile with a reverse_proxy
to the local Go service. Brace-counts to find the block end so the embedded
HTML in the original block (which contains its own braces, but balanced) is
handled correctly. Writes the new file to stdout."""
import re
import sys

NEW_BLOCK = '''ip.unt1.com {
\tencode gzip
\theader {
\t\t-Server
\t\tReferrer-Policy "no-referrer"
\t\tX-Content-Type-Options "nosniff"
\t}

\t# Forward everything to the local Go service. CF-Connecting-IP /
\t# CF-IPCountry / CF-Ray pass through unchanged from Cloudflare.
\treverse_proxy 127.0.0.1:8080 {
\t\theader_up Host {host}
\t\theader_up X-Real-IP {remote_host}
\t}
}
'''


def find_block(text: str, site: str) -> tuple[int, int]:
    # Match a top-level "<site> {" — site at start of line (allowing leading
    # whitespace) followed by an opening brace.
    pat = re.compile(r'^[ \t]*' + re.escape(site) + r'\s*\{', re.MULTILINE)
    m = pat.search(text)
    if not m:
        sys.exit(f'block for {site!r} not found')
    start = m.start()
    depth = 0
    i = m.end() - 1  # at the '{'
    while i < len(text):
        c = text[i]
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                # consume trailing newline so we don't leave a blank line.
                if end < len(text) and text[end] == '\n':
                    end += 1
                return start, end
        i += 1
    sys.exit(f'unbalanced braces in {site!r} block')


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit('usage: swap-caddy-block.py <Caddyfile>')
    src = open(sys.argv[1]).read()
    a, b = find_block(src, 'ip.unt1.com')
    out = src[:a] + NEW_BLOCK + src[b:]
    sys.stdout.write(out)


if __name__ == '__main__':
    main()
