"""Standalone login + multi-publish helper script.

Prompts for existing user credentials, then publishes a chosen project
multiple times as requested (simulating opening many tabs to publish at once).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

import requests

# --- Configuration ---
API_KEY = "AIzaSyBQNjlw9Vp4tP4VVeANzyPJnqbG2wLbYPw"
FIREBASE_BASE = "https://identitytoolkit.googleapis.com/v1"
LOVABLE_API = "https://api.lovable.dev"
DEFAULT_PASSWORD = "Euix1234!"


@dataclass
class AuthTokens:
    """Container for Firebase authentication tokens."""

    id_token: str
    email: str


def _session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "user-agent": "lovable-loginflow/0.1",
            "accept": "*/*",
        }
    )
    return session


def _auth_headers(id_token: str) -> dict:
    return {
        "authorization": f"Bearer {id_token}",
        "content-type": "application/json",
        "origin": "https://lovable.dev",
        "referer": "https://lovable.dev/",
    }


def sign_in(email: str, password: str, session: requests.Session) -> AuthTokens:
    """Login with an existing account and return auth tokens."""

    payload = {"returnSecureToken": True, "email": email, "password": password}
    resp = session.post(
        f"{FIREBASE_BASE}/accounts:signInWithPassword",
        params={"key": API_KEY},
        json=payload,
    )
    resp.raise_for_status()
    data = resp.json()
    return AuthTokens(id_token=data["idToken"], email=data["email"])


def publish_project(
    session: requests.Session, id_token: str, project_id: str, iteration: int
) -> bool:
    """Publish the specified project once.

    Returns True on success, False otherwise.
    """

    url = f"{LOVABLE_API}/projects/{project_id}/deployments"
    params = {"async": "true"}

    print(f"[{iteration}] Publishing project {project_id}...")
    resp = session.post(url, params=params, headers=_auth_headers(id_token), json={})

    if resp.ok:
        payload = resp.json()
        deployment_id = payload.get("deployment_id")
        deployment_url = payload.get("url")
        print(f"[{iteration}] Publish accepted.")
        if deployment_id:
            print(f"[{iteration}] Deployment id: {deployment_id}")
        if deployment_url:
            print(f"[{iteration}] Deployment URL: {deployment_url}")
        return True

    print(f"[{iteration}] Failed to publish: {resp.status_code} {resp.text}")
    return False


def main():
    session = _session()

    print("=== Lovable Login + Multi-Publish (Standalone) ===")
    email = input("Enter login email: ").strip()
    password = input(f"Enter password (default: {DEFAULT_PASSWORD}): ").strip() or DEFAULT_PASSWORD
    project_id = input("Enter project ID to publish: ").strip()

    if not email or not project_id:
        print("Error: email and project ID are required.")
        sys.exit(1)

    try:
        tokens = sign_in(email, password, session)
    except Exception as exc:  # noqa: BLE001 - surface login errors
        print(f"Login failed: {exc}")
        sys.exit(1)

    times_raw = input("How many times to publish? ").strip()
    try:
        total_runs = int(times_raw)
    except ValueError:
        print("Invalid number. Please enter an integer.")
        sys.exit(1)

    if total_runs <= 0:
        print("Nothing to do. Please enter a positive number.")
        sys.exit(0)

    print(f"Preparing to publish project {project_id} {total_runs} time(s)...")

    successes = 0
    for i in range(1, total_runs + 1):
        if publish_project(session, tokens.id_token, project_id, i):
            successes += 1

    print(f"Completed {successes}/{total_runs} publish attempts.")


if __name__ == "__main__":
    main()
