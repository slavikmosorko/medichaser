#!/usr/bin/env python
# PYTHON_ARGCOMPLETE_OK

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
# Copyright: (c) 2018, apqlzm - https://github.com/apqlzm/medihunter
# Copyright: (c) 2025, SteveSteve24 - https://github.com/SteveSteve24/MediCzuwacz
# Copyright: (c) 2025, rafsaf - https://github.com/rafsaf/medichaser
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import argparse
import base64
import concurrent.futures
import datetime
import hashlib
import json
import logging
import os
import pathlib
import random
import re
import select
import string
import sys
import threading
import time
import tomllib
import uuid
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from typing import Any, cast
from urllib.parse import parse_qs, quote_plus, unquote_plus, urlparse

import argcomplete
import requests
import tenacity
from dotenv import load_dotenv
from fake_useragent import UserAgent
from filelock import FileLock
from requests.adapters import HTTPAdapter
from rich.console import Console
from rich.logging import RichHandler
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium_stealth import stealth
from urllib3.util import Retry

from notifications import (
    gotify_notify,
    prowl_notify,
    pushbullet_notify,
    pushover_notify,
    telegram_notify,
    xmpp_notify,
)

CURRENT_PATH = pathlib.Path(__file__).parent.resolve()
DATA_PATH = CURRENT_PATH / "data"
DATA_PATH.mkdir(parents=True, exist_ok=True)
TOKEN_PATH = DATA_PATH / "medicover_token.json"
TOKEN_LOCK_PATH = DATA_PATH / "medicover_token.lock"
LOGIN_LOCK_PATH = DATA_PATH / "medicover_login.lock"
DEVICE_ID_PATH = DATA_PATH / "device_id.json"
DEVICE_UA_PATH = DATA_PATH / "device_ua.json"
LOG_FILE = DATA_PATH / "medichaser.log"
MEDICOVER_LOGIN_URL = "https://login-online24.medicover.pl"
MEDICOVER_MAIN_URL = "https://online24.medicover.pl"
MEDICOVER_API_URL = "https://api-gateway-online24.medicover.pl"

token_lock = FileLock(TOKEN_LOCK_PATH, timeout=60)
login_lock = FileLock(LOGIN_LOCK_PATH, timeout=60)

# Setup logging
console = Console()

logging.basicConfig(
    level="INFO",
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        RotatingFileHandler(
            LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5
        ),  # 10 MB
        RichHandler(rich_tracebacks=True, console=console),
    ],
)

log = logging.getLogger("medichaser")

# Load environment variables
load_dotenv()

retry_strategy = Retry(
    total=10,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
)
global_adapter = HTTPAdapter(max_retries=retry_strategy)


class InvalidGrantError(Exception):
    """Custom exception for invalid_grant error during token refresh."""

    pass


class ExpiredToken(Exception):
    """Retryable custom exception for expired access token."""

    pass


class MFAError(Exception):
    """Custom exception for MFA-related errors."""

    pass


class Authenticator:
    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.device_id = self._get_or_create_device_id()
        self.session.cookies.set("__mcc", self.device_id)
        self.session.mount("https://", global_adapter)
        self.headers: dict[str, str] = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "pl",
            "Connection": "keep-alive",
            "Origin": MEDICOVER_MAIN_URL,
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
            "Sec-GPC": "1",
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": "Linux",
            "User-Agent": self._get_or_create_ua(),
        }
        self.tokenA: str | None = None
        self.tokenR: str | None = None
        self.expires_at: int | None = None
        self.driver: WebDriver | None = None

    def _get_or_create_device_id(self) -> str:
        """Gets the device ID from storage or creates a new one."""
        if DEVICE_ID_PATH.exists():
            try:
                device_id_data = json.loads(DEVICE_ID_PATH.read_text())
                device_id = device_id_data.get("device_id")
                if device_id:
                    log.info(f"Using existing device ID: {device_id}")
                    return device_id  # type: ignore[no-any-return]
            except (json.JSONDecodeError, KeyError) as e:
                log.warning(
                    f"Could not read device ID file, creating a new one. Error: {e}"
                )
        device_id = str(uuid.uuid4())
        log.info(f"Creating and saving new device ID: {device_id}")
        DEVICE_ID_PATH.write_text(json.dumps({"device_id": device_id}))
        return device_id

    def _get_or_create_ua(self) -> str:
        """Gets the device UA from storage or creates a new one."""
        if DEVICE_UA_PATH.exists():
            try:
                device_ua_data = json.loads(DEVICE_UA_PATH.read_text())
                device_ua = device_ua_data.get("device_ua")
                if device_ua:
                    log.info(f"Using existing device UA: {device_ua}")
                    return device_ua  # type: ignore[no-any-return]
            except (json.JSONDecodeError, KeyError) as e:
                log.warning(
                    f"Could not read device UA file, creating a new one. Error: {e}"
                )
        ua = UserAgent(os="Linux")

        device_ua = ua.random
        log.info(f"Creating and saving new device UA: {device_ua}")
        DEVICE_UA_PATH.write_text(json.dumps({"device_ua": device_ua}))
        return device_ua

    def _load_token_from_storage(self) -> bool:
        """Loads token from the JSON file if it exists and is valid."""
        if not TOKEN_PATH.exists():
            return False

        try:
            with token_lock:
                token_data = json.loads(TOKEN_PATH.read_text())
                self.tokenA = token_data.get("access_token")
                self.tokenR = token_data.get("refresh_token")
                self.expires_at = token_data.get("expires_at")

                if not all([self.tokenA, self.tokenR, self.expires_at]):
                    log.warning("Token file is incomplete. Ignoring.")
                    TOKEN_PATH.unlink()  # Delete corrupted token file
                    return False

                if self.expires_at and self.expires_at > int(time.time()):
                    self.headers["Authorization"] = f"Bearer {self.tokenA}"
                    log.info("Successfully loaded valid token from storage.")
                    return True
                else:
                    log.info("Token from storage has expired.")
                    return False
        except (json.JSONDecodeError, KeyError) as e:
            log.warning(f"Could not read token file, ignoring. Error: {e}")
            if TOKEN_PATH.exists():
                TOKEN_PATH.unlink()
            return False

    def login_requests(self) -> None:  # pragma: no cover
        """Login using raw HTTP requests."""
        log.info("Attempting login via requests.")

        # Step 1: Initial GET to get cookies and CSRF token
        # PKCE (Proof Key for Code Exchange) Flow
        code_verifier = "".join(
            random.choice(string.ascii_uppercase + string.digits) for _ in range(50)
        )
        code_challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .decode()
            .replace("=", "")
        )
        state = uuid.uuid4().hex + uuid.uuid4().hex

        params: dict[str, str | int] = {
            "client_id": "web",
            "redirect_uri": f"{MEDICOVER_MAIN_URL}/signin-oidc",
            "response_type": "code",
            "scope": "openid offline_access profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_mode": "query",
            "ui_locales": "en",
            "app_version": "3.9.3-beta.1.8",
            "device_id": self.device_id,
            "device_name": "Chrome",
            "ts": int(time.time() * 1000),
        }

        response = self.session.get(
            f"{MEDICOVER_LOGIN_URL}/connect/authorize",
            params=params,
            headers=self.headers,
            allow_redirects=False,
        )
        response.raise_for_status()
        next_url = response.headers["Location"]
        time.sleep(2)

        response = self.session.get(
            next_url, headers=self.headers, allow_redirects=False
        )
        # Extract CSRF token from the HTML form
        match = re.search(
            r'<input name="__RequestVerificationToken" type="hidden" value="([^"]+)" />',
            response.text,
        )
        if not match:
            raise ValueError(
                "Could not find CSRF token in login page: " + response.text
            )
        csrf_token = match.group(1)
        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)
        return_url = query_params["ReturnUrl"][0]
        # Step 2: POST credentials
        login_data = {
            "Input.ReturnUrl": return_url,
            "Input.LoginType": "FullLogin",
            "Input.Username": self.username,
            "Input.Password": self.password,
            "Input.Button": "login",
            "__RequestVerificationToken": csrf_token,
        }

        time.sleep(5)

        response = self.session.post(
            f"{MEDICOVER_LOGIN_URL}/Account/Login?ReturnUrl={return_url}",
            data=login_data,
            headers={
                **self.headers,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            },
            allow_redirects=False,  # We want to handle redirects manually
        )
        log.info(
            f"Login response status: {response.status_code}, text: {response.text}, URL: {response.url}"
        )

        # Step 3: Handle redirects and potential MFA
        while response.status_code == 302:
            redirect_url = response.headers["Location"]
            if not redirect_url.startswith("https://"):
                redirect_url = MEDICOVER_LOGIN_URL + redirect_url

            log.info(f"Redirecting to: {redirect_url}")

            # Check if redirect is to MFA
            if "mfa" in redirect_url.lower():
                log.info("MFA required, handling MFA process.")
                response = self._handle_mfa(redirect_url)
                continue

            time.sleep(2)
            # Follow the redirect
            response = self.session.get(
                redirect_url, headers=self.headers, allow_redirects=False
            )

            # Check if we have the final code
            if "code" in redirect_url:
                parsed_url = urlparse(redirect_url)
                query_params = parse_qs(parsed_url.query)
                code = query_params.get("code", [None])[0]
                if code:
                    self._exchange_code_for_token(code, code_verifier)
                    return  # Success!

        # If we are here, something went wrong
        log.error(f"Login failed. Final status: {response.status_code}")
        log.error(response.text)
        raise ValueError("Login failed after handling redirects.")

    def _handle_mfa(self, mfa_url: str) -> requests.Response:  # pragma: no cover
        """Handles the MFA step of the login process."""
        log.info("MFA required.")

        # Get the MFA page
        log.info(f"Fetching MFA page: {mfa_url}")
        time.sleep(2)
        response = self.session.get(
            mfa_url,
            headers=self.headers,
            allow_redirects=False,
        )
        response.raise_for_status()

        log.info("Csrf token and MfaCodeId extraction from MFA page.")
        # Extract CSRF token from the HTML form
        match = re.search(
            r'<input name="__RequestVerificationToken" type="hidden" value="([^"]+)" />',
            response.text,
        )
        if not match:
            raise ValueError("Could not find CSRF token in mfa page: " + response.text)
        csrf_token = match.group(1)

        log.info(f"CSRF token for MFA: {csrf_token}")
        # Extract MfaCodeId from the cookie
        log.info("Extracting MfaCodeId from cookies: %s", self.session.cookies)

        mfa_info_cookie_encoded = self.session.cookies.get("MfaInfo")
        if not mfa_info_cookie_encoded:
            raise MFAError("MfaInfo cookie not found.")

        mfa_info_cookie = unquote_plus(mfa_info_cookie_encoded)

        log.info(f"MfaInfo cookie: {mfa_info_cookie}")
        try:
            mfa_info = json.loads(mfa_info_cookie)
            mfa_code_id = mfa_info.get("MfaCodeId")
            if not mfa_code_id:
                raise MFAError("MfaCodeId not found in MfaInfo cookie.")
        except json.JSONDecodeError:
            raise MFAError("Could not decode MfaInfo cookie.")
        log.info(f"MfaCodeId: {mfa_code_id}")

        # Prompt user for MFA code
        log.info("Please enter the MFA code sent to your device and press Enter:")
        rlist, _, _ = select.select([sys.stdin], [], [], 120)
        if rlist:
            mfa_code = sys.stdin.readline().rstrip("\n")
        else:
            log.error("Error getting MFA code input: Timeout expired.")
            raise MFAError("Timeout! Failed to get MFA code input.")

        if len(mfa_code) != 6 or not mfa_code.isdigit():
            log.error("MFA code must be 6 digits.")
            raise MFAError("Invalid MFA code format.")

        parsed_url = urlparse(mfa_url)
        query_params = parse_qs(parsed_url.query)
        return_url = query_params["returnUrl"][0]

        mfa_data = {
            "Input.MfaCodeId": mfa_code_id,
            "Input.ReturnUrl": return_url,
            "Input.DeviceName": "Chrome",
            "Input.MfaCode": mfa_code,
            "Input.IsTrustedDevice": "true",
            "Input.Channel": "SMS",
            "Input.Button": "confirm",
            "__RequestVerificationToken": csrf_token,
        }

        log.info("Submitting MFA code: %s", mfa_data)
        time.sleep(2)

        response = self.session.post(
            f"{MEDICOVER_LOGIN_URL}/Account/Mfa?ReturnUrl={quote_plus(return_url)}",
            data=mfa_data,
            headers={
                **self.headers,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            },
            allow_redirects=False,
        )
        log.info(
            f"MFA response status: {response.status_code}, text: {response.text}, URL: {response.url}, headers: {response.headers}"
        )
        response.raise_for_status()
        return response

    def _exchange_code_for_token(
        self, code: str, code_verifier: str
    ) -> None:  # pragma: no cover
        """Exchanges the authorization code for an access token."""
        log.info("Exchanging authorization code for token.")
        token_data = {
            "client_id": "web",
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": code_verifier,
            "redirect_uri": f"{MEDICOVER_MAIN_URL}/signin-oidc",
        }

        response = self.session.post(
            f"{MEDICOVER_LOGIN_URL}/connect/token",
            data=token_data,
            headers={
                **self.headers,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        response.raise_for_status()

        data = response.json()
        if "error" in data:
            raise ValueError(f"Failed to get token: {data['error_description']}")

        expires_in = data.get("expires_in")
        expires_at = int(time.time()) + expires_in if expires_in else None
        data["expires_at"] = expires_at

        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_PATH.write_text(json.dumps(data, indent=4))

        self.tokenA = data.get("access_token")
        self.tokenR = data.get("refresh_token")
        self.expires_at = data.get("expires_at")
        self.headers["Authorization"] = f"Bearer {self.tokenA}"
        log.info("Successfully obtained and saved tokens.")

    @login_lock
    @tenacity.retry(
        stop=tenacity.stop_after_attempt(2),
        wait=tenacity.wait_fixed(10),
        retry=tenacity.retry_if_not_exception_type(MFAError),
        reraise=True,
    )
    def login(self) -> None:
        """Orchestrates the login process."""
        try:
            log.info("Attempting to load token from file.")
            if self._load_token_from_storage():
                log.info("Attempting to refresh token.")
                self.refresh_token()
                return

        except InvalidGrantError:
            log.warning(
                "Token refresh failed with invalid grant. Proceeding to full login."
            )
        except Exception as e:
            log.error(f"An unexpected error occurred during token refresh: {e}")

        # Proceed with full login
        if os.environ.get("SELENIUM_LOGIN"):
            self.login_selenium()
        else:
            self.login_requests()

    def _init_driver(self) -> WebDriver:
        """Initializes the Selenium WebDriver if it's not already running."""
        if self.driver is None:
            options = webdriver.ChromeOptions()
            options.add_argument("--headless")  # Run in headless mode
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument(f"user-data-dir={DATA_PATH / 'chrome_profile'}")
            self.driver = webdriver.Chrome(options=options)
            stealth(
                self.driver,
                languages=["pl-PL", "pl"],
                vendor="Google Inc.",
                platform="Linux",
                webgl_vendor="Intel Inc.",
                renderer="Intel Iris OpenGL Engine",
                fix_hairline=True,
            )
            ua = self.driver.execute_cdp_cmd("Browser.getVersion", {})[
                "userAgent"
            ].replace("HeadlessChrome", "Chrome")
            self.headers["User-Agent"] = ua

            log.info(f"Creating and saving new device UA: {ua}")
            DEVICE_UA_PATH.write_text(json.dumps({"device_ua": ua}))

            log.info(f"Using User-Agent: {ua}")

        assert self.driver is not None
        return self.driver

    def _quit_driver(self) -> None:
        """Quits the Selenium WebDriver if it's running."""
        if self.driver:
            self.driver.quit()
            self.driver = None

    @token_lock
    def refresh_token(self) -> None:
        """Refresh the access token using the refresh token."""
        if (
            self.tokenA
            and self.tokenR
            and self.expires_at
            and self.expires_at > int(time.time())
        ):
            log.info("access token is still valid, no need to refresh.")
            return

        if not self.tokenR:
            log.warning("No refresh token available, cannot refresh access token.")
            return

        log.info("Refreshing access token...")
        refresh_token_data = {
            "grant_type": "refresh_token",
            "refresh_token": self.tokenR,
            "scope": "openid offline_access profile",
            "client_id": "web",
        }
        if "Authorization" in self.headers:
            del self.headers["Authorization"]  # Remove old token if present

        # Use the refresh token to get a new access token
        response = self.session.post(
            f"{MEDICOVER_LOGIN_URL}/connect/token",
            data=refresh_token_data,
            headers=self.headers,
            allow_redirects=False,
        )

        data = response.json()
        if "error" in data:
            if data["error"] == "invalid_grant":
                log.error(
                    "Refresh token is invalid or expired. Deleting token file and re-authenticating."
                )
                if TOKEN_PATH.exists():
                    TOKEN_PATH.unlink()
                raise InvalidGrantError(
                    "Invalid grant: refresh token is likely expired or revoked."
                )
            raise ValueError(
                f"Failed to refresh token: {response.status_code} {response.text}"
            )

        # manually set expires_at
        expires_in = data.get("expires_in")
        expires_at = int(time.time()) + expires_in if expires_in else None
        data["expires_at"] = expires_at

        TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_PATH.write_text(json.dumps(data, indent=4))

        self.tokenA = data.get("access_token")
        self.tokenR = data.get("refresh_token")
        self.expires_at = data.get("expires_at")
        self.headers["Authorization"] = f"Bearer {self.tokenA}"

    def _get_token_from_selenium_storage(self) -> bool:
        """Retrieves token from browser's localStorage."""
        driver = self._init_driver()
        try:
            token_data = driver.execute_script(
                f"return localStorage.getItem('oidc.user:{MEDICOVER_LOGIN_URL}/:web');"
            )
            if not token_data:
                log.warning("Token not found in localStorage.")
                return False

            token_json = json.loads(token_data)
            TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
            TOKEN_PATH.write_text(json.dumps(token_json, indent=4))

            self.tokenA = token_json.get("access_token")
            self.tokenR = token_json.get("refresh_token")
            self.expires_at = token_json.get("expires_at")
            self.headers["Authorization"] = f"Bearer {self.tokenA}"
            log.info("Successfully retrieved token from localStorage.")
            return True
        except Exception as e:
            log.error(f"Error retrieving token from localStorage: {e}")
            log.error(driver.page_source)
            return False

    def login_selenium(self) -> None:  # pragma: no cover
        log.info("No valid saved token found, attempting browser login.")
        self._quit_driver()
        driver = self._init_driver()
        wait = WebDriverWait(driver, 8)

        driver.get(MEDICOVER_LOGIN_URL)

        try:
            # Wait for a URL that indicates we are past the initial redirect
            wait.until(
                EC.any_of(
                    EC.url_contains("/Account/Login"),
                    EC.url_contains("/home"),
                    EC.url_contains("signin-oidc"),
                    EC.url_contains("/signout-callback-oidc"),
                )
            )
        except Exception:
            log.error("Page did not redirect to a known login or home URL.")
            log.error(driver.page_source)
            self._quit_driver()
            raise

        time.sleep(2)  # Allow time for the page to load

        current_url = driver.current_url
        log.debug(f"Current URL: {current_url}")

        if "/Account/Login?" in current_url:
            log.info("On login page, proceeding with login.")
        elif "/signout-callback-oidc" in current_url:
            log.info("On signout-callback-oidc page, proceeding with login.")
            driver.get(f"{MEDICOVER_LOGIN_URL}/Account/Login")
        else:
            log.info("Already logged in or on a trusted device. Fetching token...")
            time.sleep(5)  # Wait for local storage to be populated
            if self._get_token_from_selenium_storage():
                self._quit_driver()
                return
            else:
                log.warning(
                    "Failed to get token from storage, proceeding with manual login."
                )

        # --- Standard Login Flow ---
        try:
            wait.until(EC.presence_of_element_located((By.ID, "cmpwrapper")))
            driver.execute_script(
                "document.getElementById('cmpwrapper').remove(); document.body.style.overflow = 'auto';"
            )
            log.info("Attempted to remove consent manager overlay")
        except Exception:
            log.warning(
                "Could not remove consent manager overlay, or it was not present."
            )

        try:
            username_field = wait.until(
                EC.presence_of_element_located((By.ID, "usernameInput"))
            )
            password_field = wait.until(
                EC.presence_of_element_located((By.ID, "passwordInput"))
            )
            username_field.send_keys(self.username)
            password_field.send_keys(self.password)
            login_button = wait.until(
                EC.element_to_be_clickable((By.ID, "login-button"))
            )
            login_button.click()
        except Exception as e:
            log.error(f"Error during login form submission: {e}")
            log.error(driver.page_source)
            self._quit_driver()
            raise

        # --- MFA or Final Redirect ---
        try:
            wait.until(
                EC.any_of(
                    EC.url_contains("/home"),
                    EC.presence_of_element_located((By.CLASS_NAME, "mfa-pin-group")),
                )
            )
        except Exception:
            log.error("Did not redirect to MFA or home page.")
            log.error(driver.page_source)
            self._quit_driver()
            raise

        if "/home" in driver.current_url:
            log.info("Redirected to signin-oidc, MFA likely skipped. Fetching token.")
            time.sleep(5)  # Wait for local storage to be populated
            if self._get_token_from_selenium_storage():
                self._quit_driver()
                return
            else:
                log.error("Failed to get token after signin-oidc redirect.")
                self._quit_driver()
                raise ValueError("Failed to retrieve token after signin-oidc redirect.")

        # --- MFA Flow ---
        log.info("MFA page loaded")
        try:
            wait.until(EC.presence_of_element_located((By.ID, "cmpwrapper")))
            driver.execute_script(
                "document.getElementById('cmpwrapper').remove(); document.body.style.overflow = 'auto';"
            )
            log.info("Attempted to remove consent manager overlay on MFA page")
        except Exception:
            log.warning("Could not remove consent manager overlay on MFA page.")

        log.info("Please enter the MFA code sent to your device and press Enter:")
        rlist, _, _ = select.select([sys.stdin], [], [], 60)
        if rlist:
            mfa_code = sys.stdin.readline().rstrip("\n")
        else:
            log.error("Error getting MFA code input: Timeout expired.")
            self._quit_driver()
            raise MFAError("Timeout! Failed to get MFA code input.")

        if len(mfa_code) != 6 or not mfa_code.isdigit():
            log.error("MFA code must be 6 digits.")
            self._quit_driver()
            raise MFAError("Invalid MFA code format.")

        mfa_inputs = driver.find_elements(By.CSS_SELECTOR, "div.mfa-pin-group input")
        for i in range(6):
            mfa_inputs[i].send_keys(mfa_code[i])

        try:
            trusted_device_checkbox = wait.until(
                EC.element_to_be_clickable((By.ID, "isTrustedDeviceCheckbox"))
            )
            trusted_device_checkbox.click()
            mfa_button = wait.until(EC.element_to_be_clickable((By.ID, "mfa-button")))
            mfa_button.click()
        except Exception as e:
            log.error(f"Error clicking MFA button: {e}")
            log.error(driver.page_source)
            self._quit_driver()
            raise MFAError("Failed to submit MFA code.")

        time.sleep(5)  # Wait for the page to fully load and token to be stored
        if not self._get_token_from_selenium_storage():
            log.error("Failed to retrieve token after MFA.")
            self._quit_driver()
            raise MFAError("Failed to retrieve token after MFA.")

        self._quit_driver()


class AppointmentFinder:
    def __init__(self, session: requests.Session, headers: dict[str, str]) -> None:
        self.session = session
        self.headers = headers

    def http_get(self, url: str, params: dict[str, Any]) -> dict[str, Any]:
        response = self.session.get(url, headers=self.headers, params=params)
        if response.status_code in [401, 403]:
            log.error("Unauthorized access error: refreshing token.")
            raise ExpiredToken("Access token expired or invalid")
        elif response.status_code == 200:
            return cast(dict[str, Any], response.json())
        else:
            log.error(f"Error {response.status_code}: {response.text}")
            return {}

    def find_appointments(
        self,
        region: int,
        specialty: list[int],
        clinic: int | None,
        start_date: datetime.date,
        end_date: datetime.date | None,
        language: int | None,
        doctor: int | None = None,
    ) -> list[dict[str, Any]]:
        appointment_url = (
            f"{MEDICOVER_API_URL}/appointments/api/search-appointments/slots"
        )
        params: dict[str, Any] = {
            "RegionIds": region,
            "SpecialtyIds": specialty,
            "ClinicIds": clinic,
            "Page": 1,
            "PageSize": 5000,
            "StartTime": start_date.isoformat(),
            "SlotSearchType": 0,
            "VisitType": "Center",
        }

        if language:
            params["DoctorLanguageIds"] = language

        if doctor:
            params["DoctorIds"] = doctor

        response_json = self.http_get(appointment_url, params)

        items: list[dict[str, Any]] = response_json.get("items", [])

        if end_date:
            items = [
                x
                for x in items
                if datetime.datetime.fromisoformat(x["appointmentDate"]).date()
                <= end_date
            ]

        return items

    def find_filters(
        self, region: int | None = None, specialty: list[int] | None = None
    ) -> dict[str, Any]:
        filters_url = (
            f"{MEDICOVER_API_URL}/appointments/api/search-appointments/filters"
        )

        params: dict[str, Any] = {"SlotSearchType": 0}
        if region:
            params["RegionIds"] = region
        if specialty:
            params["SpecialtyIds"] = specialty

        response = self.http_get(filters_url, params)
        return response


class Notifier:
    @staticmethod
    def format_appointments(appointments: list[dict[str, Any]]) -> str:
        """Format appointments into a human-readable string."""
        if not appointments:
            return "No appointments found."

        messages = []
        for appointment in appointments:
            date = appointment.get("appointmentDate", "N/A")
            clinic = appointment.get("clinic", {}).get("name", "N/A")
            doctor = appointment.get("doctor", {}).get("name", "N/A")
            specialty = appointment.get("specialty", {}).get("name", "N/A")
            doctor_languages = appointment.get("doctorLanguages", [])
            languages = (
                ", ".join([lang.get("name", "N/A") for lang in doctor_languages])
                if doctor_languages
                else "N/A"
            )
            message = (
                f"📅 <b>Date:</b> {date}\n"
                f"🏥 <b>Clinic:</b> {clinic}\n"
                f"👨‍⚕️ <b>Doctor:</b> {doctor}\n"
                f"🗣 <b>Languages:</b> {languages}\n"
                f"🔬 <b>Specialty:</b> {specialty}\n"
                "━━━━━━━━━━━━━━━━━━━━━━"
            )
            messages.append(message)
        return "\n".join(messages)

    @staticmethod
    @tenacity.retry(
        stop=tenacity.stop_after_attempt(10),
        wait=tenacity.wait_exponential(multiplier=2, min=1),
        reraise=True,
    )
    def send_notification(
        appointments: list[dict[str, Any]],
        notifier: str | None,
        title: str | None,
    ) -> None:
        """Send a notification with formatted appointments."""
        message = Notifier.format_appointments(appointments)
        if notifier is None:
            log.info("No notifier specified, skipping notification.")
            return

        log.info("Sending notification to %s with title: %s", notifier, title)
        if notifier == "pushbullet":
            pushbullet_notify(message, title)
        elif notifier == "pushover":
            pushover_notify(message, title)
        elif notifier == "telegram":
            telegram_notify(message, title)
        elif notifier == "xmpp":
            xmpp_notify(message)
        elif notifier == "gotify":
            gotify_notify(message, title)
        elif notifier == "prowl":
            prowl_notify(message, title)
        log.info("Notification sent successfully.")


def display_appointments(
    appointments: list[dict[str, Any]], *, logger: logging.Logger | None = None
) -> None:
    active_logger = logger or log
    active_logger.info("")
    active_logger.info("--------------------------------------------------")
    if not appointments:
        active_logger.info("No new appointments found.")
    else:
        active_logger.info("New appointments found:")
        active_logger.info("--------------------------------------------------")
        for appointment in appointments:
            date = appointment.get("appointmentDate", "N/A")
            clinic = appointment.get("clinic", {}).get("name", "N/A")
            doctor = appointment.get("doctor", {}).get("name", "N/A")
            specialty = appointment.get("specialty", {}).get("name", "N/A")
            doctor_languages = appointment.get("doctorLanguages", [])
            languages = (
                ", ".join([lang.get("name", "N/A") for lang in doctor_languages])
                if doctor_languages
                else "N/A"
            )
            active_logger.info(f"Date: {date}")
            active_logger.info(f"  Clinic: {clinic}")
            active_logger.info(f"  Doctor: {doctor}")
            active_logger.info(f"  Specialty: {specialty}")
            active_logger.info(f"  Languages: {languages}")
            active_logger.info("--------------------------------------------------")


def json_date_serializer(obj: Any) -> str:
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime.date | datetime.datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class PrefixLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter that prepends a prefix to all log messages."""

    def process(self, msg: str, kwargs: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        prefix = self.extra.get("prefix", "")
        if prefix:
            msg = f"{prefix}{msg}"
        return msg, kwargs


class SeenNotificationStore:
    """Thread-safe in-memory store of sent appointment notifications."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: set[str] = set()

    def _make_key(self, appointment: dict[str, Any]) -> str:
        appointment_id = appointment.get("id")
        if appointment_id is not None:
            return str(appointment_id)

        canonical = json.dumps(appointment, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def filter_new(self, appointments: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return appointments that have not triggered a notification yet."""

        fresh: list[dict[str, Any]] = []
        with self._lock:
            for appointment in appointments:
                key = self._make_key(appointment)
                if key not in self._seen:
                    self._seen.add(key)
                    fresh.append(appointment)
        return fresh


@dataclass
class ParallelJob:
    """Configuration for a single appointment search."""

    args: argparse.Namespace
    label: str | None = None


@dataclass
class ParallelConfig:
    """Configuration for running multiple appointment searches."""

    jobs: list[ParallelJob]
    max_parallel: int | None = None


def create_job_logger(label: str | None) -> logging.Logger:
    """Return a logger that includes the job label in messages."""

    if not label:
        return log
    return PrefixLoggerAdapter(log, {"prefix": f"[{label}] "})


def _parse_date(value: Any, default: datetime.date | None = None) -> datetime.date | None:
    if value is None:
        return default
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    if isinstance(value, str):
        return datetime.date.fromisoformat(value)
    raise ValueError(f"Unsupported date value: {value!r}")


def load_parallel_config(config_path: pathlib.Path) -> ParallelConfig:
    """Load appointment jobs from a TOML configuration file."""

    try:
        with config_path.open("rb") as file:
            raw_config = tomllib.load(file)
    except FileNotFoundError as exc:
        raise ValueError(f"Configuration file not found: {config_path}") from exc

    settings = cast(dict[str, Any], raw_config.get("settings", {}))
    raw_jobs = raw_config.get("jobs")

    if not isinstance(raw_jobs, list) or not raw_jobs:
        raise ValueError("Configuration must define at least one job in [[jobs]].")

    max_parallel = settings.get("max_parallel")
    if max_parallel is not None:
        if not isinstance(max_parallel, int) or max_parallel < 1:
            raise ValueError("settings.max_parallel must be a positive integer if provided.")

    jobs: list[ParallelJob] = []
    for index, job in enumerate(raw_jobs, start=1):
        if not isinstance(job, dict):
            raise ValueError(f"Job #{index} must be a table.")

        try:
            region = int(job["region"])
        except KeyError as exc:  # pragma: no cover - validated in tests
            raise ValueError(f"Job #{index} is missing required field 'region'.") from exc
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Job #{index} has invalid region value: {job.get('region')!r}.") from exc

        specialty_value = job.get("specialty")
        if specialty_value is None:
            raise ValueError(f"Job #{index} is missing required field 'specialty'.")
        if isinstance(specialty_value, list):
            try:
                specialty = [int(item) for item in specialty_value]
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Job #{index} has invalid specialty list: {specialty_value!r}."
                ) from exc
        else:
            try:
                specialty = [int(specialty_value)]
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Job #{index} has invalid specialty value: {specialty_value!r}."
                ) from exc

        clinic = job.get("clinic")
        clinic_id = int(clinic) if clinic is not None else None

        doctor = job.get("doctor")
        doctor_id = int(doctor) if doctor is not None else None

        language = job.get("language")
        language_id = int(language) if language is not None else None

        interval = job.get("interval")
        interval_minutes = int(interval) if interval is not None else None

        start_date = _parse_date(job.get("date"), datetime.date.today())
        end_date = _parse_date(job.get("enddate"))

        notification = job.get("notification")
        if notification is not None and not isinstance(notification, str):
            raise ValueError(f"Job #{index} has invalid notification value: {notification!r}.")

        title = job.get("title")
        if title is not None and not isinstance(title, str):
            raise ValueError(f"Job #{index} has invalid title value: {title!r}.")

        label_value = job.get("label")
        label = label_value if isinstance(label_value, str) else None

        args = argparse.Namespace(
            command="find-appointment",
            region=region,
            specialty=specialty,
            clinic=clinic_id,
            doctor=doctor_id,
            date=start_date,
            enddate=end_date,
            notification=notification,
            title=title,
            language=language_id,
            interval=interval_minutes,
        )

        jobs.append(ParallelJob(args=args, label=label))

    return ParallelConfig(jobs=jobs, max_parallel=max_parallel)


class NextRun:
    def __init__(self, interval_minutes: int | None = 60) -> None:
        self.next_run = datetime.datetime.now(tz=datetime.UTC)
        self.interval_minutes = interval_minutes

    def is_time_to_run(self) -> bool:
        if self.interval_minutes is None:
            return True
        now = datetime.datetime.now(tz=datetime.UTC)
        if now >= self.next_run:
            self.next_run = now + datetime.timedelta(minutes=self.interval_minutes)
            return True
        return False

    def set_next_run(self) -> None:
        if self.interval_minutes is None:
            return
        self.next_run = datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(
            minutes=self.interval_minutes
        )


def run_find_appointment(
    args: argparse.Namespace,
    username: str,
    password: str,
    seen_store: SeenNotificationStore,
    *,
    job_label: str | None = None,
) -> None:
    job_log = create_job_logger(job_label)

    auth = Authenticator(username, password)
    try:
        auth.login()
    except MFAError:
        job_log.error("Failed MFA, please try again.")
        DEVICE_ID_PATH.unlink(missing_ok=True)
        raise

    time.sleep(5)

    finder = AppointmentFinder(auth.session, auth.headers)
    next_run = NextRun(args.interval)
    previous_appointments: list[dict[str, Any]] = []

    try:
        while True:
            try:
                auth.refresh_token()
            except InvalidGrantError as e:
                job_log.warning(f"Token refresh failed: {e}")
                job_log.info("Attempting to re-login...")
                auth.login()
                time.sleep(5)
                job_log.info("Re-login successful, continuing...")
                continue

            if not next_run.is_time_to_run():
                time.sleep(30)
                continue

            next_run.set_next_run()

            try:
                appointments = finder.find_appointments(
                    args.region,
                    args.specialty,
                    args.clinic,
                    args.date,
                    args.enddate,
                    args.language,
                    args.doctor,
                )
            except ExpiredToken as e:
                job_log.warning("Expired token error: %s", e)
                continue

            if previous_appointments:
                new_appointments = [
                    appointment
                    for appointment in appointments
                    if appointment not in previous_appointments
                ]
            else:
                new_appointments = appointments

            previous_appointments = appointments

            display_appointments(new_appointments, logger=job_log)

            fresh_appointments = seen_store.filter_new(new_appointments)
            if fresh_appointments:
                Notifier.send_notification(
                    fresh_appointments, args.notification, args.title
                )

            if next_run.interval_minutes is None:
                job_log.info("Exiting after one run due to interval set to None.")
                break
    except Exception as e:
        job_log.error(f"Error in main loop: {e}")
        Notifier.send_notification(
            [],
            args.notification,
            f"medichaser crashed during run:\n {e}",
        )
        raise


def run_parallel(
    config_path: pathlib.Path,
    username: str,
    password: str,
    seen_store: SeenNotificationStore,
    override_parallel: int | None = None,
) -> None:
    config = load_parallel_config(config_path)

    parallel_limit = override_parallel or config.max_parallel or len(config.jobs)
    if parallel_limit < 1:
        raise ValueError("Parallel limit must be at least 1.")

    if len(config.jobs) > parallel_limit:
        log.info(
            "Running %s jobs with a parallel limit of %s. Remaining jobs will start when slots free up.",
            len(config.jobs),
            parallel_limit,
        )
    else:
        log.info(
            "Running %s jobs with a parallel limit of %s.",
            len(config.jobs),
            parallel_limit,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel_limit) as executor:
        futures = [
            executor.submit(
                run_find_appointment,
                job.args,
                username,
                password,
                seen_store,
                job_label=job.label,
            )
            for job in config.jobs
        ]

        try:
            for future in concurrent.futures.as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            log.info("Received interrupt, cancelling parallel jobs.")
            for future in futures:
                future.cancel()
            raise
        except Exception as exc:  # pragma: no cover - safety net
            log.error("Parallel appointment job terminated with exception: %s", exc)
            for future in futures:
                future.cancel()
            raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Find appointment slots.")

    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Command to execute"
    )

    find_appointment = subparsers.add_parser(
        "find-appointment", help="Find appointment"
    )
    find_appointment.add_argument(
        "-r", "--region", required=True, type=int, help="Region ID"
    )
    find_appointment.add_argument(
        "-s",
        "--specialty",
        required=True,
        type=int,
        action="extend",
        nargs="+",
        help="Specialty ID",
    )
    find_appointment.add_argument(
        "-c", "--clinic", required=False, type=int, help="Clinic ID"
    )
    find_appointment.add_argument(
        "-d", "--doctor", required=False, type=int, help="Doctor ID"
    )
    find_appointment.add_argument(
        "-f",
        "--date",
        type=datetime.date.fromisoformat,
        default=datetime.date.today(),
        help="Start date in YYYY-MM-DD format",
    )
    find_appointment.add_argument(
        "-e",
        "--enddate",
        type=datetime.date.fromisoformat,
        help="End date in YYYY-MM-DD format",
    )
    find_appointment.add_argument(
        "-n", "--notification", required=False, help="Notification method"
    )
    find_appointment.add_argument(
        "-t", "--title", required=False, help="Notification title"
    )
    find_appointment.add_argument(
        "-l",
        "--language",
        required=False,
        type=int,
        help="4=Polski, 6=Angielski, 60=Ukraiński",
    )
    find_appointment.add_argument(
        "-i",
        "--interval",
        type=int,
        default=None,
        help="Repeat interval in minutes",
    )

    find_appointments = subparsers.add_parser(
        "find-appointments",
        help="Run multiple appointment searches in parallel",
    )
    find_appointments.add_argument(
        "-c",
        "--config",
        required=True,
        type=pathlib.Path,
        help="Path to TOML configuration file with [[jobs]] entries",
    )
    find_appointments.add_argument(
        "-m",
        "--max-parallel",
        type=int,
        help="Override maximum number of concurrent searches",
    )

    list_filters = subparsers.add_parser("list-filters", help="List filters")
    list_filters_subparsers = list_filters.add_subparsers(
        dest="filter_type", required=True, help="Type of filter to list"
    )

    list_filters_subparsers.add_parser("regions", help="List available regions")
    list_filters_subparsers.add_parser("specialties", help="List available specialties")
    doctors = list_filters_subparsers.add_parser(
        "doctors", help="List available doctors"
    )
    doctors.add_argument("-r", "--region", required=True, type=int, help="Region ID")
    doctors.add_argument(
        "-s", "--specialty", required=True, type=int, help="Specialty ID"
    )
    clinics = list_filters_subparsers.add_parser(
        "clinics", help="List available clinics"
    )
    clinics.add_argument("-r", "--region", required=True, type=int, help="Region ID")
    clinics.add_argument(
        "-s", "--specialty", required=True, type=int, nargs="+", help="Specialty ID(s)"
    )

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    username = os.environ.get("MEDICOVER_USER")
    password = os.environ.get("MEDICOVER_PASS")

    if not username or not password:
        log.error(
            "MEDICOVER_USER and MEDICOVER_PASS environment variables must be set."
        )
        sys.exit(1)

    seen_store = SeenNotificationStore()

    if args.command == "find-appointment":
        run_find_appointment(
            args,
            username,
            password,
            seen_store,
        )
        return

    if args.command == "find-appointments":
        run_parallel(
            args.config,
            username,
            password,
            seen_store,
            args.max_parallel,
        )
        return

    auth = Authenticator(username, password)
    try:
        auth.login()
    except MFAError:
        log.error("Failed MFA, please try again.")
        DEVICE_ID_PATH.unlink(missing_ok=True)
        raise

    time.sleep(5)

    finder = AppointmentFinder(auth.session, auth.headers)

    if args.command == "list-filters":
        # Authenticate
        try:
            auth.refresh_token()
        except InvalidGrantError as e:
            log.warning(f"Token refresh failed: {e}")
            log.info("Attempting to re-login...")
            auth.login()
            time.sleep(5)
            log.info("Re-login successful, continuing...")
        except Exception as e:
            log.error(f"Error refreshing token: {e}")
            Notifier.send_notification(
                [],
                args.notification,
                f"medichaser crashed while refreshing token\n: {e}",
            )
            raise
        if args.filter_type in ("doctors", "clinics"):
            filters = finder.find_filters(args.region, args.specialty)
        else:
            filters = finder.find_filters()

        for r in filters[args.filter_type]:
            log.info(f"{r['id']} - {r['value']}")


if __name__ == "__main__":
    main()
