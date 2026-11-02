#!/usr/bin/env python3
"""Idempotently add a Tomcat Connector for APP_B_PORT if missing."""
from __future__ import annotations

import os
import sys
from pathlib import Path

PORT = os.environ.get("APP_B_PORT", "8090")


def main() -> int:
    xml_path = Path(sys.argv[1] if len(sys.argv) > 1 else "/etc/tomcat/server.xml")
    text = xml_path.read_text(encoding="utf-8")
    needle = f'port="{PORT}"'
    if needle in text:
        print(f"connector {PORT} already present in {xml_path}")
        return 0
    connector = (
        f'    <Connector port="{PORT}" protocol="HTTP/1.1"\n'
        f'               connectionTimeout="20000"\n'
        f'               redirectPort="8443" />\n'
    )
    marker = "</Service>"
    if marker not in text:
        print(f"no </Service> in {xml_path}", file=sys.stderr)
        return 1
    xml_path.write_text(text.replace(marker, connector + marker, 1), encoding="utf-8")
    print(f"inserted connector {PORT} into {xml_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
