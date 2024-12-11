import base64
import hashlib
import json
import os
import random
import re
import string
import uuid
import argparse
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from fake_useragent import UserAgent
from future.backports.urllib.parse import parse_qs
from rich import print_json, print
from rich.console import Console

from medihunter_notifiers import pushbullet_notify, pushover_notify, telegram_notify, xmpp_notify, gotify_notify

console = Console()

# Load environment variables
load_dotenv()

class Authenticator:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.headers = {
            "User-Agent": UserAgent().random,
            "Accept": "application/json",
            "Authorization": None
        }
        self.tokenA = None

    def generate_code_challenge(self, input):
        sha256 = hashlib.sha256(input.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(sha256).decode("utf-8").rstrip("=")

    def login(self):
        state = "".join(random.choices(string.ascii_lowercase + string.digits, k=32))
        device_id = str(uuid.uuid4())
        code_verifier = "".join(uuid.uuid4().hex for _ in range(3))
        code_challenge = self.generate_code_challenge(code_verifier)

        login_url = "https://login-online24.medicover.pl"
        oidc_redirect = "https://online24.medicover.pl/signin-oidc"
        auth_params = (
            f"?client_id=web&redirect_uri={oidc_redirect}&response_type=code"
            f"&scope=openid+offline_access+profile&state={state}&code_challenge={code_challenge}"
            "&code_challenge_method=S256&response_mode=query&ui_locales=pl&app_version=3.2.0.482"
            "&previous_app_version=3.2.0.482&device_id={device_id}&device_name=Chrome"
        )

        # Step 1: Initialize login
        response = self.session.get(f"{login_url}/connect/authorize{auth_params}", headers=self.headers, allow_redirects=False)
        next_url = response.headers.get("Location")

        # Step 2: Extract CSRF token
        response = self.session.get(next_url, headers=self.headers, allow_redirects=False)
        soup = BeautifulSoup(response.content, "html.parser")
        csrf_token = soup.find("input", {"name": "__RequestVerificationToken"}).get("value")

        # Step 3: Submit login form
        login_data = {
            "Input.ReturnUrl": f"/connect/authorize/callback{auth_params}",
            "Input.LoginType": "FullLogin",
            "Input.Username": self.username,
            "Input.Password": self.password,
            "Input.Button": "login",
            "__RequestVerificationToken": csrf_token,
        }
        response = self.session.post(next_url, data=login_data, headers=self.headers, allow_redirects=False)
        next_url = response.headers.get("Location")

        # Step 4: Fetch authorization code
        response = self.session.get(f"{login_url}{next_url}", headers=self.headers, allow_redirects=False)
        next_url = response.headers.get("Location")
        code = parse_qs(urlparse(next_url).query)["code"][0]

        # Step 5: Exchange code for tokens
        token_data = {
            "grant_type": "authorization_code",
            "redirect_uri": oidc_redirect,
            "code": code,
            "code_verifier": code_verifier,
            "client_id": "web",
        }
        response = self.session.post(f"{login_url}/connect/token", data=token_data, headers=self.headers)
        tokens = response.json()
        self.tokenA = tokens["access_token"]
        self.headers["Authorization"] = f"Bearer {self.tokenA}"

class AppointmentFinder:
    def __init__(self, session, headers):
        self.session = session
        self.headers = headers

    def find_appointments(self, region, specialty, clinic, start_date):
        appointment_url = (
            "https://api-gateway-online24.medicover.pl/appointments/api/search-appointments/slots"
        )
        params = {
            "RegionIds": region,
            "SpecialtyIds": specialty,
            "ClinicIds": clinic,
            "Page": 1,
            "PageSize": 5000,
            "StartTime": start_date,
            "SlotSearchType": 0,
            "VisitType": "Center",
        }
        response = self.session.get(appointment_url, headers=self.headers, params=params)
        if response.status_code == 200:
            return response.json().get("items", [])
        else:
            console.print(f"[bold red]Error {response.status_code}[/bold red]: {response.text}")
            return []

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
            message = (
                f"Date: {date}\n"
                f"Clinic: {clinic}\n"
                f"Doctor: {doctor}\n"
                f"Specialty: {specialty}\n"
                + "-" * 50
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
    if not appointments:
        console.print("No appointments found.")
    else:
        for appointment in appointments:
            date = appointment.get("appointmentDate", "N/A")
            clinic = appointment.get("clinic", {}).get("name", "N/A")
            doctor = appointment.get("doctor", {}).get("name", "N/A")
            specialty = appointment.get("specialty", {}).get("name", "N/A")
            console.print(f"Date: {date}")
            console.print(f"  Clinic: {clinic}")
            console.print(f"  Doctor: {doctor}")
            console.print(f"  Specialty: {specialty}")
            console.print("-" * 50)

def main():
    parser = argparse.ArgumentParser(description="Find appointment slots.")
    parser.add_argument("command", choices=["find-appointment"], help="Command to execute")
    parser.add_argument("-r", "--region", required=True, type=int, help="Region ID")
    parser.add_argument("-s", "--specialty", required=True, type=int, help="Specialty ID")
    parser.add_argument("-c", "--clinic", required=False, type=int, help="Clinic ID")
    parser.add_argument("-f", "--date", required=True, help="Start date in YYYY-MM-DD format")
    parser.add_argument("-n", "--notification", required=False, help="Notification method")
    parser.add_argument("-t", "--title", required=False, help="Notification title")
    args = parser.parse_args()

    username = os.environ.get("MEDICOVER_USER")
    password = os.environ.get("MEDICOVER_PASS")

    # Authenticate
    auth = Authenticator(username, password)
    auth.login()

    # Find appointments
    finder = AppointmentFinder(auth.session, auth.headers)
    appointments = finder.find_appointments(args.region, args.specialty, args.clinic, args.date)

    # Display appointments
    display_appointments(appointments)

    # Send notification if appointments are found
    if appointments:
        Notifier.send_notification(appointments, args.notification, args.title)

if __name__ == "__main__":
    main()
