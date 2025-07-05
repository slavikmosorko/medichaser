#!/usr/bin/python3

import argparse
import datetime
import json
import os
import pathlib
import sys
import time

import requests
from dotenv import load_dotenv
from fake_useragent import UserAgent
from filelock import FileLock
from requests.adapters import HTTPAdapter
from rich import print
from rich.console import Console
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium_stealth import stealth
from urllib3.util import Retry

from medihunter_notifiers import (
    gotify_notify,
    pushbullet_notify,
    pushover_notify,
    telegram_notify,
    xmpp_notify,
)

CURRENT_PATH = pathlib.Path(__file__).parent.resolve()
DATA_PATH = CURRENT_PATH / "data"
TOKEN_PATH = DATA_PATH / "medicover_token.json"
TOKEN_LOCK_PATH = DATA_PATH / "medicover_token.lock"

token_lock = FileLock(TOKEN_LOCK_PATH, timeout=10)
console = Console()

# Load environment variables
load_dotenv()

retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    connect=5,
    read=5,
    redirect=5,
)
global_adapter = HTTPAdapter(max_retries=retry_strategy)


class InvalidGrantError(Exception):
    """Custom exception for invalid_grant error during token refresh."""

    pass


class Authenticator:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session.mount("https://", global_adapter)
        self.headers = {
            "User-Agent": UserAgent().random,
            "Accept": "application/json",
        }
        self.tokenA = None
        self.tokenR = None
        self.expires_at = None
        self.driver = None

    def _init_driver(self):
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
                platform="Win32",
                webgl_vendor="Intel Inc.",
                renderer="Intel Iris OpenGL Engine",
                fix_hairline=True,
            )
        return self.driver

    def _quit_driver(self):
        """Quits the Selenium WebDriver if it's running."""
        if self.driver:
            self.driver.quit()
            self.driver = None

    @token_lock
    def refresh_token(self):
        """Refresh the access token using the refresh token."""
        if (
            self.tokenA
            and self.tokenR
            and self.expires_at
            and self.expires_at > int(time.time())
        ):
            print("access token is still valid, no need to refresh.")
            return

        if not self.tokenR:
            print("No refresh token available, cannot refresh access token.")
            return

        print("Refreshing access token...")
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
            "https://login-online24.medicover.pl/connect/token",
            data=refresh_token_data,
            headers=self.headers,
            allow_redirects=False,
        )

        data = response.json()
        if "error" in data:
            if data["error"] == "invalid_grant":
                print(
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

    def use_saved_token(self):
        """Load saved token from file if it exists."""
        if TOKEN_PATH.exists():
            with open(TOKEN_PATH) as f:
                token_data = json.load(f)
                self.tokenA = token_data.get("access_token")
                self.tokenR = token_data.get("refresh_token")
                self.expires_at = token_data.get("expires_at")
                self.expires_in = token_data.get("expires_in")
                if self.expires_at and self.expires_at < int(time.time()):
                    print("access token expired, refreshing...")
                    self.refresh_token()

                if self.tokenA and self.tokenR:
                    self.headers["Authorization"] = f"Bearer {self.tokenA}"
                    print("Using saved access token.")
                    return True
        return False

    def _get_token_from_storage(self):
        """Retrieves token from browser's localStorage."""
        driver = self._init_driver()
        try:
            token_data = driver.execute_script(
                "return localStorage.getItem('oidc.user:https://login-online24.medicover.pl/:web');"
            )
            if not token_data:
                print("Token not found in localStorage.")
                return False

            token_json = json.loads(token_data)
            TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
            TOKEN_PATH.write_text(json.dumps(token_json, indent=4))

            self.tokenA = token_json.get("access_token")
            self.tokenR = token_json.get("refresh_token")
            self.expires_at = token_json.get("expires_at")
            self.headers["Authorization"] = f"Bearer {self.tokenA}"
            print("Successfully retrieved token from localStorage.")
            return True
        except Exception as e:
            print(f"Error retrieving token from localStorage: {e}")
            print(driver.page_source)
            return False

    def login(self) -> None:
        # if self.use_saved_token():
        #     return

        print("No valid saved token found, attempting browser login.")
        driver = self._init_driver()
        wait = WebDriverWait(driver, 10)

        driver.get("https://login-online24.medicover.pl/")

        try:
            # Wait for a URL that indicates we are past the initial redirect
            wait.until(
                EC.any_of(
                    EC.url_contains("/Account/Login"),
                    EC.url_contains("/home"),
                    EC.url_contains("signin-oidc"),
                )
            )
        except Exception:
            print("Page did not redirect to a known login or home URL.")
            print(driver.page_source)
            self._quit_driver()
            sys.exit(1)

        current_url = driver.current_url
        print(f"Current URL: {current_url}")

        if "/home" in current_url or "signin-oidc" in current_url:
            print("Already logged in or on a trusted device. Fetching token...")
            time.sleep(5)  # Wait for local storage to be populated
            if self._get_token_from_storage():
                self._quit_driver()
                return
            else:
                print("Failed to get token from storage, proceeding with manual login.")

        # --- Standard Login Flow ---
        try:
            wait.until(EC.presence_of_element_located((By.ID, "cmpwrapper")))
            driver.execute_script(
                "document.getElementById('cmpwrapper').remove(); document.body.style.overflow = 'auto';"
            )
            print("Attempted to remove consent manager overlay")
        except Exception:
            print("Could not remove consent manager overlay, or it was not present.")

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
            print(f"Error during login form submission: {e}")
            print(driver.page_source)
            self._quit_driver()
            sys.exit(1)

        # --- MFA or Final Redirect ---
        try:
            wait.until(
                EC.any_of(
                    EC.url_contains("/home"),
                    EC.presence_of_element_located((By.CLASS_NAME, "mfa-pin-group")),
                )
            )
        except Exception:
            print("Did not redirect to MFA or home page.")
            print(driver.page_source)
            self._quit_driver()
            sys.exit(1)

        if "/home" in driver.current_url:
            print("Redirected to signin-oidc, MFA likely skipped. Fetching token.")
            time.sleep(5)  # Wait for local storage to be populated
            if self._get_token_from_storage():
                self._quit_driver()
                return
            else:
                print("Failed to get token after signin-oidc redirect.")
                self._quit_driver()
                sys.exit(1)

        # --- MFA Flow ---
        print("MFA page loaded")
        try:
            wait.until(EC.presence_of_element_located((By.ID, "cmpwrapper")))
            driver.execute_script(
                "document.getElementById('cmpwrapper').remove(); document.body.style.overflow = 'auto';"
            )
            print("Attempted to remove consent manager overlay on MFA page")
        except Exception:
            print("Could not remove consent manager overlay on MFA page.")

        mfa_code = input("Please enter the 6-digit MFA code: ")
        if len(mfa_code) != 6 or not mfa_code.isdigit():
            print("MFA code must be 6 digits.")
            self._quit_driver()
            sys.exit(1)

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
            print(f"Error clicking MFA button: {e}")
            print(driver.page_source)
            self._quit_driver()
            sys.exit(1)

        time.sleep(5)  # Wait for the page to fully load and token to be stored
        if not self._get_token_from_storage():
            print("Failed to retrieve token after MFA.")
            self._quit_driver()
            sys.exit(1)

        self._quit_driver()


class AppointmentFinder:
    def __init__(self, session, headers):
        self.session = session
        self.headers = headers

    def http_get(self, url, params):
        response = self.session.get(url, headers=self.headers, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            console.print(
                f"[bold red]Error {response.status_code}[/bold red]: {response.text}"
            )
            return {}

    def find_appointments(
        self, region, specialty, clinic, start_date, end_date, language, doctor=None
    ):
        appointment_url = "https://api-gateway-online24.medicover.pl/appointments/api/search-appointments/slots"
        params = {
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

        response = self.http_get(appointment_url, params)

        items = response.get("items", [])

        if end_date:
            items = [
                x
                for x in items
                if datetime.datetime.fromisoformat(x["appointmentDate"]).date()
                <= end_date
            ]

        return items

    def find_filters(self, region=None, specialty=None):
        filters_url = "https://api-gateway-online24.medicover.pl/appointments/api/search-appointments/filters"

        params = {"SlotSearchType": 0}
        if region:
            params["RegionIds"] = region
        if specialty:
            params["SpecialtyIds"] = specialty

        response = self.http_get(filters_url, params)
        return response


class Notifier:
    @staticmethod
    def format_appointments(appointments):
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
                f"Date: {date}\n"
                f"Clinic: {clinic}\n"
                f"Doctor: {doctor}\n"
                f"Languages: {languages}\n" + f"Specialty: {specialty}\n" + "-" * 50
            )
            messages.append(message)
        return "\n".join(messages)

    @staticmethod
    def send_notification(appointments, notifier, title):
        """Send a notification with formatted appointments."""
        message = Notifier.format_appointments(appointments)
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


def display_appointments(appointments):
    console.print()
    console.print("-" * 50)
    if not appointments:
        console.print("No new appointments found.")
    else:
        console.print("New appointments found:")
        console.print("-" * 50)
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
            console.print(f"Date: {date}")
            console.print(f"  Clinic: {clinic}")
            console.print(f"  Doctor: {doctor}")
            console.print(f"  Specialty: {specialty}")
            console.print(f"  Languages: {languages}")
            console.print("-" * 50)


def json_date_serializer(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime.date | datetime.datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


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


def main():
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
        "-i", "--interval", required=False, type=int, help="Repeat interval in minutes"
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

    args = parser.parse_args()

    username = os.environ.get("MEDICOVER_USER")
    password = os.environ.get("MEDICOVER_PASS")

    if not username or not password:
        console.print(
            "[bold red]Error:[/bold red] MEDICOVER_USER and MEDICOVER_PASS environment variables must be set."
        )
        sys.exit(1)

    previous_appointments = []

    auth = Authenticator(username, password)
    auth.login()

    if args.interval:
        Notifier.send_notification(
            [],
            args.notification,
            f"Mediczuwacz started in interval with command: {args.command} and arguments: {json.dumps(vars(args), indent=2, default=json_date_serializer)}",
        )

    next_run = NextRun(args.interval)

    while True:
        # Authenticate
        try:
            auth.refresh_token()
        except InvalidGrantError as e:
            console.print(f"[bold yellow]Token refresh failed:[/bold yellow] {e}")
            console.print("[bold yellow]Attempting to re-login...[/bold yellow]")
            auth.login()
            console.print("[bold green]Re-login successful, continuing...[/bold green]")
            continue
        except Exception as e:
            console.print(f"[bold red]Error refreshing token:[/bold red] {e}")
            Notifier.send_notification(
                [],
                args.notification,
                f"Mediczuwacz crashed while refreshing token\n: {e}",
            )
            raise

        finder = AppointmentFinder(auth.session, auth.headers)

        if args.command == "find-appointment":
            if not next_run.is_time_to_run():
                time.sleep(30)
                continue

            next_run.set_next_run()

            # Find appointments
            appointments = finder.find_appointments(
                args.region,
                args.specialty,
                args.clinic,
                args.date,
                args.enddate,
                args.language,
                args.doctor,
            )

            # Find new appointments
            if previous_appointments:
                new_appointments = [
                    x for x in appointments if x not in previous_appointments
                ]
            else:
                new_appointments = appointments

            previous_appointments = appointments

            # Display appointments
            display_appointments(new_appointments)

            # Send notification if appointments are found
            if new_appointments:
                Notifier.send_notification(
                    new_appointments, args.notification, args.title
                )

            if next_run.interval_minutes is None:
                console.print(
                    "[bold green]Exiting after one run due to interval set to None.[/bold green]"
                )
                break

            continue

        elif args.command == "list-filters":
            if args.filter_type in ("doctors", "clinics"):
                filters = finder.find_filters(args.region, args.specialty)
            else:
                filters = finder.find_filters()

            for r in filters[args.filter_type]:
                print(f"{r['id']} - {r['value']}")

        break


if __name__ == "__main__":
    main()
