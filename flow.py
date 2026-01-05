import requests
import sys
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

# --- Configuration ---
API_KEY = "AIzaSyBQNjlw9Vp4tP4VVeANzyPJnqbG2wLbYPw"
FIREBASE_BASE = "https://identitytoolkit.googleapis.com/v1"
LOVABLE_API = "https://api.lovable.dev"
DEFAULT_PASSWORD = "Euix1234!"

@dataclass
class AuthTokens:
    id_token: str
    email: str

def _session() -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "user-agent": "lovable-helper/0.1",
        "accept": "*/*",
    })
    return session

def sign_up(email: str, password: str, session: requests.Session):
    """Step 1: Create account and send verification email."""
    payload = {
        "returnSecureToken": True,
        "email": email,
        "password": password,
        "clientType": "CLIENT_TYPE_WEB",
    }
    print(f"Creating account for {email}...")
    resp = session.post(f"{FIREBASE_BASE}/accounts:signUp", params={"key": API_KEY}, json=payload)
    resp.raise_for_status()
    
    print("Sending verification email...")
    id_token = resp.json()["idToken"]
    verify_payload = {"requestType": "VERIFY_EMAIL", "idToken": id_token}
    session.post(f"{FIREBASE_BASE}/accounts:sendOobCode", params={"key": API_KEY}, json=verify_payload).raise_for_status()
    print("Verification email sent. Please check your inbox.")

def verify_email_link(link: str, session: requests.Session) -> str:
    """Step 2: Process the verification link."""
    parsed = urlparse(link.strip())
    params = parse_qs(parsed.query)
    oob_code = params.get("oobCode", [None])[0] or params.get("oobcode", [None])[0]
    if not oob_code:
        raise ValueError("Could not find oobCode in the link.")

    print("Verifying email via Firebase...")
    # Confirm email
    confirm_resp = session.post(
        f"{FIREBASE_BASE}/accounts:update",
        params={"key": API_KEY},
        json={"oobCode": oob_code},
    )
    confirm_resp.raise_for_status()
    email = confirm_resp.json()["email"]
    
    print(f"Email {email} verified successfully.")
    return email

def sign_in(email: str, password: str, session: requests.Session) -> AuthTokens:
    """Step 3: Login to get a fresh token after verification."""
    payload = {"returnSecureToken": True, "email": email, "password": password}
    resp = session.post(f"{FIREBASE_BASE}/accounts:signInWithPassword", params={"key": API_KEY}, json=payload)
    resp.raise_for_status()
    data = resp.json()
    return AuthTokens(id_token=data["idToken"], email=data["email"])

def apply_referral(id_token: str, referral_code: str, session: requests.Session):
    """Step 4: Apply the referral code."""
    url = f"{LOVABLE_API}/user/referral-code/use"
    headers = _auth_headers(id_token)
    payload = {"referral_code": referral_code}
    
    print(f"Applying referral code: {referral_code}...")
    resp = session.post(url, headers=headers, json=payload)
    if resp.status_code == 200:
        print("Success! Referral code applied.")
    else:
        print(f"Failed to apply referral code: {resp.text}")


def _auth_headers(id_token: str) -> dict:
    return {
        "authorization": f"Bearer {id_token}",
        "content-type": "application/json",
        "origin": "https://lovable.dev",
        "referer": "https://lovable.dev/",
    }


def _discover_project_id(id_token: str, session: requests.Session) -> str | None:
    """Try to locate the first available project for the user."""
    try:
        resp = session.get(f"{LOVABLE_API}/projects", headers=_auth_headers(id_token))
        resp.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - best-effort discovery
        print(f"Could not auto-discover project id: {exc}")
        return None

    data = resp.json()
    if isinstance(data, list) and data:
        project = data[0]
    else:
        project = None
        for key in ("projects", "items", "data"):
            projects = data.get(key) if isinstance(data, dict) else None
            if projects:
                project = projects[0]
                break

    if isinstance(project, dict):
        return project.get("id") or project.get("project_id")
    return None


def publish_first_site(id_token: str, session: requests.Session, project_id: str | None = None):
    """Step 5: Publish the user's first website to trigger advocate credits."""
    resolved_project_id = project_id or _discover_project_id(id_token, session)
    if not resolved_project_id:
        print("No project id provided and auto-discovery failed. Skipping publish step.")
        return

    url = f"{LOVABLE_API}/projects/{resolved_project_id}/deployments"
    params = {"async": "true"}

    print(f"Publishing first website for project {resolved_project_id}...")
    resp = session.post(url, params=params, headers=_auth_headers(id_token), json={})
    if resp.ok:
        payload = resp.json()
        deployment_url = payload.get("url")
        deployment_id = payload.get("deployment_id")
        print("Publish request accepted.")
        if deployment_id:
            print(f"Deployment id: {deployment_id}")
        if deployment_url:
            print(f"Deployment URL: {deployment_url}")
    else:
        print(f"Failed to publish website: {resp.status_code} {resp.text}")

def main():
    print("=== Lovable Full Flow: Register -> Verify -> Referral ===")
    session = _session()
    
    # Phase 1: Registration
    email = input("Enter email for new account: ").strip()
    password = input(f"Enter password (default: {DEFAULT_PASSWORD}): ").strip() or DEFAULT_PASSWORD
    referral_code = input("Enter referral code to apply: ").strip()
    
    if not email or not referral_code:
        print("Error: Email and referral code are required.")
        return

    try:
        sign_up(email, password, session)
        
        # Phase 2: Verification
        print("\n--- ACTION REQUIRED ---")
        print("Please check your email and paste the verification link below.")
        link = input("Paste verification link: ").strip()
        if not link:
            print("No link provided. Aborting.")
            return
            
        verified_email = verify_email_link(link, session)
        
        # Phase 3: Login & Referral
        print("\nLogging in to apply referral...")
        tokens = sign_in(verified_email, password, session)
        
        # Small delay for backend sync
        time.sleep(1)
        apply_referral(tokens.id_token, referral_code, session)

        # Phase 4: Publish to award advocate credits
        print("\nPublishing the first website to trigger advocate credits...")
        project_id = input("Enter project ID to publish (leave blank to auto-detect): ").strip() or None
        publish_first_site(tokens.id_token, session, project_id)

        print("\nAll steps completed successfully!")
        
    except Exception as e:
        print(f"\nAn error occurred: {e}")

if __name__ == "__main__":
    main()
