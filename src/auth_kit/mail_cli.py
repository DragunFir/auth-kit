from __future__ import annotations

import argparse
import sys

from .core.config import get_settings
from .services import send_test_mail


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Send a test mail using the current auth-kit SMTP configuration.")
    parser.add_argument("--to", required=True, help="Recipient email address")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        settings = get_settings()
        send_test_mail(to_email=args.to, settings=settings)
    except Exception as exc:
        print(f"[auth-kit] test mail failed: {exc}", file=sys.stderr)
        return 1

    print(f"[auth-kit] test mail sent to {args.to}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
