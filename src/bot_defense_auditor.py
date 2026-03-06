"""
Bot Defense profile discovery and fetching from F5 BIG-IP.

All operations are read-only against the BIG-IP device.
Profiles are fetched via the iControl REST API:
  GET /mgmt/tm/security/bot-defense/profile
  GET /mgmt/tm/security/bot-defense/profile/~{partition}~{name}
"""
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .bigip_client import BigIPClient
from .utils import get_logger, ensure_dir

_BD_PROFILE_EP = "/mgmt/tm/security/bot-defense/profile"


class BotDefenseAuditor:
    """
    Discovers and fetches Bot Defense profiles from a BIG-IP device.
    """

    def __init__(
        self,
        client: BigIPClient,
        output_dir: str,
        partitions: Optional[List[str]] = None,
    ):
        self.client = client
        self.fetch_dir = ensure_dir(Path(output_dir) / "bot-defense")
        self.filter_partitions = [p.strip() for p in partitions] if partitions else []
        self.log = get_logger("bot_defense_auditor")

    # ── Discovery ──────────────────────────────────────────────────────────────

    def discover_profiles(self, all_partitions: List[str]) -> List[Dict]:
        """
        Return a list of Bot Defense profile metadata dicts, filtered by
        partition if ``--partitions`` was specified.

        Each dict has: name, fullPath, partition, template, enforcementMode.
        """
        self.log.info("Discovering Bot Defense profiles …")
        try:
            data = self.client.get(_BD_PROFILE_EP)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to enumerate Bot Defense profiles: {exc}"
            ) from exc

        profiles: List[Dict] = []
        for item in data.get("items", []):
            full_path = item.get("fullPath", "")
            if not full_path.startswith("/"):
                full_path = f"/Common/{full_path}"

            parts = full_path.strip("/").split("/", 1)
            partition = parts[0] if len(parts) == 2 else "Common"

            if self.filter_partitions and partition not in self.filter_partitions:
                continue
            if all_partitions and partition not in all_partitions:
                continue

            profiles.append({
                "name":            item.get("name", ""),
                "fullPath":        full_path,
                "partition":       partition,
                "template":        item.get("template", ""),
                "enforcementMode": item.get("enforcementMode", "transparent"),
            })

        self.log.info("Discovered %d Bot Defense profile(s).", len(profiles))
        return profiles

    # ── Fetching ───────────────────────────────────────────────────────────────

    def fetch_profile(self, profile: Dict) -> Dict:
        """
        Fetch the full Bot Defense profile JSON from BIG-IP.

        The profile is also saved to disk under output_dir/bot-defense/ for
        the audit trail.  Returns the raw JSON dict from the API.
        """
        full_path = profile["fullPath"]
        encoded = full_path.strip("/").replace("/", "~")
        api_path = f"{_BD_PROFILE_EP}/~{encoded}"

        self.log.info("Fetching Bot Defense profile: %s", full_path)
        data = self.client.get(api_path)

        # Persist to disk for audit trail
        safe_name = full_path.strip("/").replace("/", "_")
        local_path = self.fetch_dir / f"{safe_name}.json"
        local_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        self.log.debug("Saved profile JSON to %s", local_path)

        profile["local_path"] = str(local_path)
        return data

    def fetch_all(
        self, profiles: List[Dict]
    ) -> Tuple[List[Tuple[Dict, Dict]], List[Tuple[Dict, str]]]:
        """
        Fetch all profiles sequentially.

        Returns:
            (successes, failures)
            successes: list of (profile_meta_dict, profile_data_dict)
            failures:  list of (profile_meta_dict, error_message)
        """
        successes: List[Tuple[Dict, Dict]] = []
        failures: List[Tuple[Dict, str]] = []

        for profile in profiles:
            try:
                data = self.fetch_profile(profile)
                successes.append((profile, data))
            except Exception as exc:
                msg = str(exc)
                self.log.error(
                    "Failed to fetch Bot Defense profile %s: %s",
                    profile["fullPath"], msg,
                )
                failures.append((profile, msg))

        return successes, failures

    # ── Display ────────────────────────────────────────────────────────────────

    def print_discovery_table(self, profiles: List[Dict]) -> None:
        """Print a summary table of discovered Bot Defense profiles to stdout."""
        if not profiles:
            print("No Bot Defense profiles found.")
            return

        col_widths = {
            "fullPath":        max(len("Profile Full Path"),
                                   max(len(p["fullPath"]) for p in profiles)),
            "partition":       max(len("Partition"),
                                   max(len(p["partition"]) for p in profiles)),
            "enforcementMode": max(len("Enforcement"),
                                   max(len(p["enforcementMode"]) for p in profiles)),
            "template":        max(len("Template"),
                                   max(len(p.get("template", "")) for p in profiles)),
        }
        sep = "-" * (
            col_widths["fullPath"] + col_widths["partition"] +
            col_widths["enforcementMode"] + col_widths["template"] + 24
        )
        fmt = (
            f"{{:<{col_widths['fullPath'] + 2}}}"
            f"{{:<{col_widths['partition'] + 2}}}"
            f"{{:<{col_widths['enforcementMode'] + 2}}}"
            f"{{:<{col_widths['template'] + 2}}}"
        )
        print("\n" + sep)
        print(fmt.format("Profile Full Path", "Partition", "Enforcement", "Template"))
        print(sep)
        for p in profiles:
            print(fmt.format(
                p["fullPath"],
                p["partition"],
                p["enforcementMode"],
                p.get("template", ""),
            ))
        print(sep)
        print(f"Total: {len(profiles)} Bot Defense profile(s)\n")
