import os, json
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

def load_and_refresh_token(scopes, token_path):
    if not os.path.exists(token_path):
        raise RuntimeError("Gmail token not found.")

    # Load existing token
    with open(token_path, 'r') as f:
        existing_token_data = json.load(f)

    creds = Credentials.from_authorized_user_info(existing_token_data, scopes)

    # Workaround: Restore refresh token if it’s missing from current creds
    if not creds.refresh_token and 'refresh_token' in existing_token_data:
        creds.refresh_token = existing_token_data['refresh_token']

    # Refresh if needed
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(token_path, 'w') as token_file:
            token_file.write(creds.to_json())

    return creds
