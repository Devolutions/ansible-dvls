from ansible_collections.devolutions.dvls.plugins.module_utils.http import (
    request as http_request,
)


def public_instance_information(server_base_url, token):
    url = f"{server_base_url}/api/public-instance-information"
    headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = http_request("GET", url, headers=headers)
        return response.json()
    except Exception as e:
        raise Exception(
            f"An error occurred while fetching public instance information: {e}"
        )


def private_instance_information(server_base_url, token):
    url = f"{server_base_url}/api/private-instance-information"
    headers = {"Content-Type": "application/json", "tokenId": token}

    try:
        response = http_request("GET", url, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise Exception(
            f"An error occurred while fetching private instance information: {e}"
        )
