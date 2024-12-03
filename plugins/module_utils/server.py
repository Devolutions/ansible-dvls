import requests
import json

def public_instance_information(server_base_url, token):
    url = f"{server_base_url}/api/public-instance-information"
    headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    response = requests.get(url, headers=headers)
    try:
        return response.json()
    except ValueError:
        return {}

def private_instance_information(server_base_url, token):
    url = f"{server_base_url}/api/private-instance-information"
    headers = {
        "Content-Type": "application/json",
        "tokenId": token
    }

    response = requests.get(url, headers=headers)
    try:
        return response.json()
    except ValueError:
        return {}
