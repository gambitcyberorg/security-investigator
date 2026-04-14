#!/usr/bin/env python3
"""Generate a Defender XDR Advanced Hunting deep link URL from a KQL query.

Encoding: UTF-16LE → GZip → Base64url (RFC 4648 §5)

The Defender portal decodes the query parameter as:
  Base64url decode → GZip decompress → UTF-16LE decode

Usage:
    # From a string
    python scripts/kql_to_ah_url.py "DeviceInfo | where Timestamp > ago(1d) | take 10"

    # Markdown link output (ready to paste into reports)
    python scripts/kql_to_ah_url.py --md "DeviceInfo | where Timestamp > ago(1d) | take 10"

    # From a .kql file
    python scripts/kql_to_ah_url.py --file temp/query.kql

    # From stdin (pipe)
    echo "DeviceInfo | take 10" | python scripts/kql_to_ah_url.py

Output:
    URL only (default), or markdown link (--md flag).

Rendering in reports:
    Place the link immediately after the KQL code block in every Take Action section:

        ```kql
        EmailEvents
        | where Timestamp > ago(7d)
        | where NetworkMessageId in ("<id1>", "<id2>")
        ```
        [▶ Run in Advanced Hunting](<url>)
"""

import base64
import gzip
import io
import sys
import argparse


def kql_to_ah_url(kql: str) -> str:
    """Encode a KQL query into a Defender XDR Advanced Hunting deep link.

    The portal expects: UTF-16LE bytes → GZip compressed → Base64url encoded.
    """
    # Normalize line endings to CRLF (what the portal Monaco editor expects)
    kql = kql.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")

    # UTF-16LE encode
    kql_bytes = kql.encode("utf-16-le")

    # GZip compress
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        gz.write(kql_bytes)
    compressed = buf.getvalue()

    # Base64url encode (RFC 4648 §5: +→-, /→_, no padding)
    b64 = base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")

    return f"https://security.microsoft.com/hunting?query={b64}"


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Defender XDR Advanced Hunting deep link from KQL."
    )
    parser.add_argument("kql", nargs="?", help="KQL query string")
    parser.add_argument("--file", "-f", help="Read KQL from a file")
    parser.add_argument(
        "--md", action="store_true",
        help="Output as a markdown link: [▶ Run in Advanced Hunting](url)"
    )
    args = parser.parse_args()

    # Read KQL from argument, file, or stdin
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            kql = f.read().strip()
    elif args.kql:
        kql = args.kql.strip()
    elif not sys.stdin.isatty():
        kql = sys.stdin.read().strip()
    else:
        parser.error("Provide KQL as an argument, via --file, or pipe to stdin.")
        return

    url = kql_to_ah_url(kql)

    if args.md:
        print(f"[▶ Run in Advanced Hunting]({url})")
    else:
        print(url)


if __name__ == "__main__":
    main()
