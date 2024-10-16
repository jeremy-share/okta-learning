import json
import os
import requests
from dotenv import load_dotenv

def main():
    print("Starting...")
    # Load environment variables from .env file
    root_dir = os.path.realpath(os.path.dirname(os.path.realpath(__file__)) + "/..")
    load_dotenv(dotenv_path=f"{root_dir}/.env")

    config_options = [
        "OKTA_ORG_NAME",
        "OKTA_BASE_URL",
        "OKTA_CLIENT_ID",
        "OKTA_CLIENT_SECRET",
        "OKTA_USERNAME",
        "OKTA_PASSWORD",
    ]
    config = {}
    for config_option in config_options:
        config[config_option] = os.getenv(config_option)
        if not config[config_option]:
            config[config_option] = input(f"{config_option}: ")

    # Define the base URL for Okta API
    base_url = f"https://{config['OKTA_ORG_NAME']}.{config['OKTA_BASE_URL']}"

    print(json.dumps({
        "client_id": config['OKTA_CLIENT_ID'],
        #"client_secret": config['OKTA_CLIENT_SECRET'],
        "username": config['OKTA_USERNAME'],
        #"password": config['OKTA_PASSWORD'],
        "base_url": base_url,
    }, indent=4))

    # Step 1: Get the authorization token (authorization code flow with resource owner password)
    token_url = f"{base_url}/oauth2/v1/token"

    # Set up the payload for the token request
    token_payload = {
        "grant_type": "password",
        "client_id": config['OKTA_CLIENT_ID'],
        "client_secret": config['OKTA_CLIENT_SECRET'],
        "username": config['OKTA_USERNAME'],
        "password": config['OKTA_PASSWORD'],
        "scope": "openid okta.apps.read",  # Scopes for access to apps
    }

    # Request access token
    token_response = requests.post(token_url, data=token_payload)

    if token_response.status_code == 200:
        token_data = token_response.json()
        access_token = token_data.get("access_token")
        print(f"Access Token: {access_token}")
    else:
        print("Failed to obtain access token.")
        print(token_response.json())
        exit(1)

    # Step 2: Use the access token to retrieve a list of all apps
    apps_url = f"{base_url}/api/v1/apps"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    # Make the request to get the list of apps
    apps_response = requests.get(apps_url, headers=headers)

    if apps_response.status_code == 200:
        apps_data = apps_response.json()
        print("List of Applications:")
        for app in apps_data:
            print(f"- {app['label']}")
    else:
        print("Failed to retrieve apps list.")
        print(apps_response.json())

if __name__ == "__main__":
    main()
