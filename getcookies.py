#!/usr/bin/env python3
"""
ig2playwright_autosave.py
Login to Instagram using instagrapi and export Playwright storage state JSON.
This version prompts interactively for login and AUTOSAVES output files
using the detected Instagram username (no output prompt).
"""

import json
import os
import time
import urllib.parse
import logging
import getpass
from instagrapi import Client
from instagrapi.exceptions import ChallengeRequired, TwoFactorRequired, PleaseWaitFewMinutes, RateLimitError

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def future_expiry(days=365):
    return int(time.time()) + days*24*3600

def convert_instagrapi_settings_to_playwright(insta_settings_path: str, playwright_path: str):
    with open(insta_settings_path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except Exception as e:
            raise RuntimeError(f"Invalid JSON in {insta_settings_path}: {e}")

    cookies = []
    auth = data.get("authorization_data", {}) or data.get("session", {}) or {}
    if isinstance(data.get("cookies"), dict) and data.get("cookies"):
        cookie_source = data["cookies"]
    else:
        cookie_source = auth

    for name, value in cookie_source.items():
        if value is None:
            continue
        try:
            val = urllib.parse.unquote(str(value))
        except Exception:
            val = str(value)
        cookies.append({
            "name": str(name),
            "value": val,
            "domain": ".instagram.com",
            "path": "/",
            "expires": future_expiry(365),
            "httpOnly": True,
            "secure": True,
            "sameSite": "Lax"
        })

    seen = set((c['name'], c['value']) for c in cookies)
    def recurse_collect(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (str, int)) and len(str(v)) > 5 and len(str(k)) < 40:
                    key = str(k)
                    val = urllib.parse.unquote(str(v))
                    tup = (key, val)
                    if tup not in seen:
                        cookies.append({
                            "name": key,
                            "value": val,
                            "domain": ".instagram.com",
                            "path": "/",
                            "expires": future_expiry(365),
                            "httpOnly": True,
                            "secure": True,
                            "sameSite": "Lax"
                        })
                        seen.add(tup)
                else:
                    recurse_collect(v)
        elif isinstance(obj, list):
            for i in obj:
                recurse_collect(i)

    if len(cookies) < 3:
        recurse_collect(data)

    playwright_state = {
        "cookies": cookies,
        "origins": [
            {"origin": "https://www.instagram.com", "localStorage": []}
        ]
    }

    with open(playwright_path, "w", encoding="utf-8") as f:
        json.dump(playwright_state, f, indent=2, ensure_ascii=False)

    logging.info(f"Saved Playwright state to {playwright_path} (cookies: {len(cookies)})")

def instagrapi_login_and_export(identifier: str, password: str):
    cl = Client()

    # Try to load a pre-existing file if it exists for this identifier (helps with reuse)
    probable_session_file = f"{identifier}_session.json"
    if os.path.exists(probable_session_file):
        try:
            cl.load_settings(probable_session_file)
            logging.info(f"Loaded existing settings from {probable_session_file} (may speed up login)")
        except Exception:
            logging.info("Couldn't load pre-existing settings; continuing with fresh login")

    try:
        logging.info("Attempting login...")
        cl.login(identifier, password)

        # Try to detect the canonical username from the logged-in account
        try:
            info = cl.account_info()
            detected_username = info.get("username") if isinstance(info, dict) else None
        except Exception:
            detected_username = None

        # Fallbacks if detection fails:
        if not detected_username:
            # instagrapi sometimes sets client.username attribute
            detected_username = getattr(cl, "username", None)
        if not detected_username:
            # as ultimate fallback, use the identifier the user provided (may be phone/email)
            detected_username = identifier

        # Normalize filename-safe
        safe_name = "".join(c for c in detected_username if c.isalnum() or c in ("_", "-")).lower() or "instagram_user"

        session_file = f"{safe_name}_session.json"
        playwright_file = f"{safe_name}_state.json"

        # Dump instagrapi settings to session_file
        cl.dump_settings(session_file)
        logging.info(f"Saved instagrapi session to {session_file}")

        # Convert and save Playwright state
        convert_instagrapi_settings_to_playwright(session_file, playwright_file)

        return {"detected_username": detected_username, "session_file": session_file, "state_file": playwright_file}
    except TwoFactorRequired:
        raise RuntimeError("2FA required. This script does not auto-handle 2FA. Resolve manually or implement interactive 2FA.")
    except ChallengeRequired:
        raise RuntimeError("Challenge required (email/phone verification). Resolve challenge manually or implement handlers.")
    except (PleaseWaitFewMinutes, RateLimitError):
        raise RuntimeError("Rate limited by Instagram; try again later.")
    except Exception as e:
        raise RuntimeError(f"Login failed: {e}")

def main():
    print("Instagram -> Playwright state exporter (autosave using detected username)")
    identifier = input("Login (username / phone / email): ").strip()
    if not identifier:
        print("Login identifier required. Exiting.")
        return
    password = getpass.getpass("Password (hidden): ").strip()
    if not password:
        print("Password required. Exiting.")
        return

    try:
        res = instagrapi_login_and_export(identifier, password)
        print("\nSUCCESS")
        print(f"Detected username: {res['detected_username']}")
        print(f"Session file: {res['session_file']}")
        print(f"Playwright state: {res['state_file']}")
        print("\nUse Playwright like:\n  browser.new_context(storage_state='"+res['state_file']+"')")
    except Exception as e:
        print("\nERROR:", e)
        logging.exception("Error during login/export")

if __name__ == "__main__":
    main()