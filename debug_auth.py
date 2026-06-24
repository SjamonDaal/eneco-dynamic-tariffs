#!/usr/bin/env python3
"""
Standalone debug script for the Eneco authentication flow.

Usage:
    pip install aiohttp
    python debug_auth.py

Runs the full Okta IDX flow interactively and prints every step so you can
see exactly what Eneco/Okta returns. No Home Assistant required.
"""

import asyncio
import getpass
import json
import re
import sys
from typing import Any

try:
    import aiohttp
except ImportError:
    sys.exit("aiohttp is required: pip install aiohttp")

API_BASE = "https://api-digital.enecogroup.com"
API_KEY = "41ff1058fc7f4446b80db84e8857c347"
ENECO_WEB_BASE = "https://www.eneco.nl"
OKTA_BASE = "https://inloggen.eneco.nl"


def _unescape_okta(s: str) -> str:
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)


async def post_json(session: aiohttp.ClientSession, url: str, payload: dict) -> dict:
    async with session.post(
        url,
        data=json.dumps(payload),
        headers={"Content-Type": "application/json"},
    ) as resp:
        return await resp.json(content_type=None)


def section(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print("=" * 60)


def show_state(state: dict, step: int) -> None:
    print(f"\n[IDX step {step}] top-level keys: {list(state.keys())}")

    for msg in state.get("messages", {}).get("value", []):
        print(f"  ⚠  Okta message: {msg.get('message')}")

    for rem in state.get("remediation", {}).get("value", []):
        print(f"  form '{rem.get('name')}' → {rem.get('href')}")
        for field in rem.get("value", []):
            opts = f", options={[o.get('label') for o in field.get('options', [])]}" if field.get("options") else ""
            print(
                f"    field name={field.get('name')!r:30s} "
                f"secret={str(field.get('secret', False)):5s} "
                f"has_value={str('value' in field):5s}"
                f"{opts}"
            )


async def main() -> None:
    import os
    print("Eneco authentication debug script")
    username = os.environ.get("ENECO_USER") or input("Email address: ")
    password = os.environ.get("ENECO_PASS") or getpass.getpass("Password: ")

    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar()) as session:

        # ── Step 1 ────────────────────────────────────────────────────
        section("1  Load mijn-eneco (seed cookies)")
        async with session.get(f"{ENECO_WEB_BASE}/mijn-eneco/") as resp:
            print(f"  status: {resp.status}")

        # ── Step 2 ────────────────────────────────────────────────────
        section("2  Get NextAuth CSRF token")
        async with session.get(f"{ENECO_WEB_BASE}/api/auth/csrf/") as resp:
            csrf_data = await resp.json(content_type=None)
            print(f"  response: {csrf_data}")
        csrf_token = csrf_data.get("csrfToken")
        if not csrf_token:
            sys.exit("ERROR: no csrfToken in response")

        # ── Step 3 ────────────────────────────────────────────────────
        section("3  Initiate Okta signin")
        async with session.post(
            f"{ENECO_WEB_BASE}/api/auth/signin/okta/",
            data={"json": "true", "csrfToken": csrf_token, "callbackUrl": "/mijn-eneco/"},
        ) as resp:
            print(f"  status: {resp.status}")
            okta_init = await resp.json(content_type=None)
            print(f"  response: {okta_init}")
        okta_url = okta_init.get("url")
        if not okta_url:
            sys.exit("ERROR: no 'url' key in signin response")

        # ── Step 4 ────────────────────────────────────────────────────
        section(f"4  Load Okta login page")
        print(f"  url: {okta_url}")
        async with session.get(okta_url) as resp:
            okta_html = await resp.text()
            print(f"  status: {resp.status}, html length: {len(okta_html)}")

        m = re.search(r'"stateToken"\s*:\s*"(.*?)"', okta_html)
        if not m:
            print("  WARNING: stateToken not found — first 2000 chars of HTML:")
            print(okta_html[:2000])
            sys.exit("ERROR: stateToken not found")
        state_token = _unescape_okta(m.group(1))
        print(f"  stateToken (first 20 chars): {state_token[:20]}...")

        # ── Step 5 ────────────────────────────────────────────────────
        section("5  Introspect stateToken")
        state = await post_json(
            session, f"{OKTA_BASE}/idp/idx/introspect", {"stateToken": state_token}
        )

        # ── IDX loop ──────────────────────────────────────────────────
        section("6  IDX remediation loop")
        password_submitted = False
        step = 0

        while "success" not in state:
            show_state(state, step)

            remediations = state.get("remediation", {}).get("value", [])
            if not remediations:
                msgs = state.get("messages", {}).get("value", [])
                detail = msgs[0].get("message", "no remediations") if msgs else "no remediations"
                sys.exit(f"\nERROR: authentication blocked — {detail}")

            form = remediations[0]
            href = form.get("href")
            if not href:
                sys.exit(f"ERROR: form '{form.get('name')}' has no action URL")

            post: dict[str, Any] = {}
            totp_needed = False

            for field in form.get("value", []):
                name = field.get("name", "")
                is_secret = field.get("secret", False)

                if name == "identifier":
                    post[name] = username
                elif name == "credentials":
                    if password_submitted:
                        totp_needed = True
                        break
                    post[name] = {"passcode": password}
                    password_submitted = True
                elif name == "authenticator":
                    options = field.get("options", [])
                    chosen = next(
                        (
                            opt["value"]
                            for opt in options
                            if isinstance(opt.get("value"), dict)
                            and opt["value"].get("methodType") == "password"
                        ),
                        options[0]["value"] if options else None,
                    )
                    if chosen is not None:
                        post[name] = chosen
                        print(f"  → selected authenticator: {chosen}")
                elif "value" in field and not is_secret:
                    post[name] = field["value"]

            if totp_needed:
                print("\n  *** Email TOTP challenge detected ***")
                totp_code = (os.environ.get("ENECO_TOTP") or input("  Enter the code from your email: ")).strip()
                post = {}
                for field in form.get("value", []):
                    name = field.get("name", "")
                    is_secret = field.get("secret", False)
                    if name == "credentials" and is_secret:
                        post[name] = {"passcode": totp_code}
                    elif "value" in field and not is_secret:
                        post[name] = field["value"]

            print(f"  → posting to {href}")
            print(f"     keys in body: {list(post.keys())}")
            state = await post_json(session, href, post)
            step += 1

            if step > 20:
                print("\nFull final state:")
                print(json.dumps(state, indent=2, default=str))
                sys.exit("ERROR: too many IDX steps")

        # ── Extract tokens ─────────────────────────────────────────────
        section("7  Follow success URL")
        success_href = state["success"]["href"]
        print(f"  url: {success_href}")
        async with session.get(success_href) as resp:
            success_html = await resp.text()
            print(f"  status: {resp.status}, html length: {len(success_html)}")

        tok = re.search(r'"idToken"\s*:\s*"(.*?)"', success_html)
        cid = re.search(r'"customerId"\s*:\s*(\d+)', success_html)
        aid = re.search(r'"accountId"\s*:\s*(\d+)', success_html)

        print(f"  idToken found:   {bool(tok)}")
        print(f"  customerId:      {cid.group(1) if cid else 'NOT FOUND'}")
        print(f"  accountId:       {aid.group(1) if aid else 'NOT FOUND'}")

        if not tok:
            print("  HTML snippet (first 1000 chars):")
            print(success_html[:1000])
            sys.exit("ERROR: idToken not found")

        # ── Test API ───────────────────────────────────────────────────
        section("8  Test products API endpoint")
        headers = {"apikey": API_KEY, "Authorization": f"Bearer {tok.group(1)}"}
        customer_id = cid.group(1)
        account_id = aid.group(1)
        url = (
            f"{API_BASE}/dxpweb/v2/nl/eneco/customers/{customer_id}"
            f"/accounts/{account_id}/products?includeproductrates=true"
        )
        print(f"  url: {url}")
        async with session.get(url, headers=headers) as resp:
            print(f"  status: {resp.status}")
            data = await resp.json(content_type=None)
            print(json.dumps(data, indent=2, default=str))

        section("✓ Done")


if __name__ == "__main__":
    asyncio.run(main())
