import traceback

try:
    import requests
except ImportError:
    HAS_REQUESTS_LIBRARY = False
    REQUESTS_LIBRARY_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_REQUESTS_LIBRARY_LIBRARY = True
    REQUESTS_LIBRARY_IMPORT_ERROR = None


def public_instance_information(server_base_url, token):
    url = f"{server_base_url}/api/public-instance-information"
    headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        raise Exception(
            f"An error occurred while fetching public instance information: {e}"
        )


def private_instance_information(server_base_url, token):
    url = f"{server_base_url}/api/private-instance-information"
    headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise Exception(
            f"An error occurred while fetching private instance information: {e}"
        )
