#!/usr/bin/env python3
"""
register_validator_example.py

Observer ノードをバリデータとして登録/解除するサンプル (Python 版)。
依存: requests (pip install requests)

使い方:
  # 登録
  python3 scripts/register_validator_example.py register \
    --public-key 0xabcdef... \
    --address 203.0.113.10:16110

  # 解除 (public_key または address で指定)
  python3 scripts/register_validator_example.py deregister \
    --address 203.0.113.10:16110

  # 環境変数で seed URL を指定可能
  MISAKA_SEED_URL=https://testnet.misaka-network.com \
    python3 scripts/register_validator_example.py ...
"""

import argparse
import json
import os
import sys

try:
    import requests
except ImportError:
    print("Error: 'requests' package is required.  pip install requests", file=sys.stderr)
    sys.exit(1)

DEFAULT_SEED_URL = "https://testnet.misaka-network.com"


def register_validator(seed_url: str, public_key: str, network_address: str) -> dict:
    url = f"{seed_url}/api/register_validator"
    payload = {
        "public_key": public_key,
        "network_address": network_address,
    }
    resp = requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def deregister_validator(
    seed_url: str,
    public_key: str | None = None,
    network_address: str | None = None,
) -> dict:
    url = f"{seed_url}/api/deregister_validator"
    payload = {}
    if public_key:
        payload["public_key"] = public_key
    if network_address:
        payload["network_address"] = network_address
    resp = requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_committee(seed_url: str) -> dict:
    url = f"{seed_url}/api/get_committee"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def main():
    parser = argparse.ArgumentParser(description="Register / deregister a MISAKA validator node")
    sub = parser.add_subparsers(dest="command", help="sub-command")

    reg = sub.add_parser("register", help="Register a validator")
    reg.add_argument("--public-key", required=True, help="0x-prefixed hex public key")
    reg.add_argument("--address", required=True, help="IP:PORT reachable by peers")
    reg.add_argument("--seed-url", default=None, help="Seed node URL (or set MISAKA_SEED_URL)")

    dereg = sub.add_parser("deregister", help="Deregister a validator")
    dereg.add_argument("--public-key", default=None, help="0x-prefixed hex public key")
    dereg.add_argument("--address", default=None, help="IP:PORT to remove")
    dereg.add_argument("--seed-url", default=None, help="Seed node URL (or set MISAKA_SEED_URL)")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    seed_url = args.seed_url or os.environ.get("MISAKA_SEED_URL", DEFAULT_SEED_URL)

    if args.command == "register":
        print(f"Registering validator with {seed_url}")
        print(f"  PK:   {args.public_key[:20]}...{args.public_key[-8:]}")
        print(f"  Addr: {args.address}")
        print()
        result = register_validator(seed_url, args.public_key, args.address)
        print(f"Response: {json.dumps(result, indent=2)}")
        if result.get("ok"):
            print("\nSuccess. Fetching committee...")
            committee = get_committee(seed_url)
            print(json.dumps(committee, indent=2))
        else:
            print(f"\nFailed: {result.get('error', 'unknown')}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "deregister":
        if not args.public_key and not args.address:
            print("Error: must provide --public-key and/or --address", file=sys.stderr)
            sys.exit(1)
        print(f"Deregistering validator from {seed_url}")
        if args.public_key:
            print(f"  PK:   {args.public_key[:20]}...{args.public_key[-8:]}")
        if args.address:
            print(f"  Addr: {args.address}")
        print()
        result = deregister_validator(seed_url, args.public_key, args.address)
        print(f"Response: {json.dumps(result, indent=2)}")
        if result.get("ok"):
            print("\nDeregistration successful. Fetching committee...")
            committee = get_committee(seed_url)
            print(json.dumps(committee, indent=2))
        else:
            print(f"\nFailed: {result.get('error', 'unknown')}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
