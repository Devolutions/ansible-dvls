from ansible_collections.devolutions.dvls.plugins.module_utils.http import (
    raise_for_dvls_error,
)


def server_info(session):
    try:
        response = session.request("GET", "server/info")
        raise_for_dvls_error(response)
        return response.json()
    except Exception as e:
        raise Exception(f"An error occurred while fetching the server information: {e}")
