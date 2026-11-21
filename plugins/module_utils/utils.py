from ansible_collections.devolutions.dvls.plugins.module_utils.vaults import (
    get_vault_entry,
)


def get_sensible_value(session, vault_id, entries):
    """Read every listed entry and return its data keyed by entry name.

    Raises when two different entries share a name, since one would hide the other, and when an
    entry cannot be read, since a partial result would pass for a complete one.
    """
    if isinstance(entries, dict) and "data" in entries:
        entries = entries.get("data", [])

    if not isinstance(entries, list):
        raise ValueError(f"Expected list of entries, got {type(entries).__name__}")

    ids_by_name = {}
    for secret in entries:
        if not isinstance(secret, dict):
            continue

        entry_name = secret.get("name")
        entry_id = secret.get("id")
        if not entry_name or not entry_id:
            continue

        known_id = ids_by_name.setdefault(entry_name, entry_id)
        if known_id != entry_id:
            raise ValueError(
                f"Several entries are named '{entry_name}' ({known_id}, {entry_id}), so the result "
                "cannot hold both. Fetch them with secret_id."
            )

    fetched_secrets = {}
    for entry_name, entry_id in ids_by_name.items():
        entry = get_vault_entry(session, vault_id, entry_id)
        if isinstance(entry, dict) and "data" in entry:
            fetched_secrets[entry_name] = entry["data"]

    return fetched_secrets
