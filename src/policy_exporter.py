"""
Policy discovery, export initiation, polling, and download.

All export operations are read-only against the BIG-IP device.
"""
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .bigip_client import BigIPClient
from .utils import get_logger, normalize_full_path, policy_export_filename, ensure_dir

_POLL_INTERVAL = 3       # seconds between status polls
_POLL_TIMEOUT  = 120     # max seconds to wait for a single export task


class ExportError(Exception):
    pass


class PolicyExporter:
    """
    Discovers all ASM/AWAF policies across partitions and exports them.
    """

    _PARTITION_EP = "/mgmt/tm/auth/partition"
    _POLICY_EP    = (
        "/mgmt/tm/asm/policies"
        "?$select=id,name,fullPath,active,enforcementMode,type,"
        "versionDatetime,hasParent,protocolIndependent"
    )
    _EXPORT_TASK_EP   = "/mgmt/tm/asm/tasks/export-policy"
    _DOWNLOAD_BASE_EP = "/mgmt/tm/asm/file-transfer/downloads"

    def __init__(
        self,
        client: BigIPClient,
        output_dir: str,
        export_format: str = "xml",
        concurrent_exports: int = 3,
        partitions: Optional[List[str]] = None,
    ):
        self.client = client
        self.export_dir = ensure_dir(Path(output_dir) / "exports")
        self.export_format = export_format
        self.concurrent = concurrent_exports
        self.filter_partitions = [p.strip() for p in partitions] if partitions else []
        self.log = get_logger("policy_exporter")

    # ── Discovery ──────────────────────────────────────────────────────────────

    def discover_partitions(self) -> List[str]:
        """Return all user partition names (always including 'Common')."""
        self.log.info("Discovering partitions …")
        try:
            data = self.client.get(self._PARTITION_EP)
            names = [item["name"] for item in data.get("items", [])]
        except Exception as exc:
            self.log.warning("Could not enumerate partitions (%s); defaulting to Common.", exc)
            names = []
        if "Common" not in names:
            names.insert(0, "Common")
        self.log.info("Found partitions: %s", names)
        return names

    def discover_policies(self, partitions: List[str]) -> List[Dict]:
        """Return a list of policy metadata dicts filtered by partition list."""
        self.log.info("Enumerating ASM/AWAF policies …")
        try:
            data = self.client.get(self._POLICY_EP)
        except Exception as exc:
            raise ExportError(f"Failed to enumerate policies: {exc}") from exc

        policies = []
        for item in data.get("items", []):
            full_path = item.get("fullPath", "")
            # Normalize path to always have /partition/name form
            if not full_path.startswith('/'):
                full_path = f"/Common/{full_path}"
                item["fullPath"] = full_path

            # Extract partition from fullPath
            parts = full_path.strip('/').split('/', 1)
            partition = parts[0] if len(parts) == 2 else "Common"
            item["partition"] = partition

            # Apply partition filter
            if self.filter_partitions and partition not in self.filter_partitions:
                continue

            if partition not in partitions:
                continue

            policies.append({
                "id":              item.get("id", ""),
                "name":            item.get("name", ""),
                "fullPath":        full_path,
                "partition":       partition,
                "active":          bool(item.get("active", False)),
                "enforcementMode": item.get("enforcementMode", "transparent"),
                "type":            item.get("type", "security"),
                "versionDatetime": item.get("versionDatetime", ""),
            })

        self.log.info("Discovered %d ASM/AWAF policies.", len(policies))
        return policies

    def print_discovery_table(self, policies: List[Dict]) -> None:
        """Print a summary table of all discovered policies to stdout."""
        if not policies:
            print("No ASM/AWAF policies found.")
            return
        col_widths = {
            "fullPath":        max(len("Policy Full Path"),
                                   max(len(p["fullPath"]) for p in policies)),
            "partition":       max(len("Partition"),
                                   max(len(p["partition"]) for p in policies)),
            "enforcementMode": max(len("Enforcement"),
                                   max(len(p["enforcementMode"]) for p in policies)),
            "type":            max(len("Type"),
                                   max(len(p["type"]) for p in policies)),
        }
        sep = "-" * (
            col_widths["fullPath"] + col_widths["partition"] +
            col_widths["enforcementMode"] + col_widths["type"] + 24
        )
        fmt = (
            f"{{:<{col_widths['fullPath']+2}}}"
            f"{{:<{col_widths['partition']+2}}}"
            f"{{:<{col_widths['enforcementMode']+2}}}"
            f"{{:<{col_widths['type']+2}}}"
            f"{{:<8}}"
        )
        print("\n" + sep)
        print(fmt.format("Policy Full Path", "Partition", "Enforcement", "Type", "Active"))
        print(sep)
        for p in policies:
            print(fmt.format(
                p["fullPath"],
                p["partition"],
                p["enforcementMode"],
                p["type"],
                "Yes" if p["active"] else "No",
            ))
        print(sep)
        print(f"Total: {len(policies)} policies\n")

    # ── Export workflow ────────────────────────────────────────────────────────

    def export_all(
        self, policies: List[Dict]
    ) -> Tuple[List[Dict], List[Tuple[Dict, str]]]:
        """
        Export all policies concurrently.

        Returns:
            (successes, failures)
            successes: policy dicts enriched with 'local_path'
            failures:  list of (policy_dict, error_message)
        """
        successes: List[Dict] = []
        failures: List[Tuple[Dict, str]] = []
        total = len(policies)

        self.log.info("Exporting %d policies (concurrency=%d) …", total, self.concurrent)

        with ThreadPoolExecutor(max_workers=self.concurrent) as pool:
            future_to_policy = {
                pool.submit(self._export_one, policy, idx + 1, total): policy
                for idx, policy in enumerate(policies)
            }
            for future in as_completed(future_to_policy):
                policy = future_to_policy[future]
                try:
                    local_path = future.result()
                    policy["local_path"] = str(local_path)
                    successes.append(policy)
                except Exception as exc:
                    msg = str(exc)
                    self.log.error(
                        "Export FAILED for %s: %s", policy["fullPath"], msg
                    )
                    failures.append((policy, msg))

        return successes, failures

    def _export_one(
        self, policy: Dict, index: int, total: int
    ) -> Path:
        """Full export lifecycle for a single policy. Returns local file path."""
        full_path = policy["fullPath"]
        policy_id = policy["id"]
        self.log.info("Exporting policy %d/%d: %s …", index, total, full_path)

        filename = policy_export_filename(full_path, self.export_format)

        # Step 1 – initiate export task
        task_resp = self.client.post(
            self._EXPORT_TASK_EP,
            data={
                "filename": filename,
                "format": self.export_format,
                "minimal": False,
                "policyReference": {
                    "link": f"https://localhost/mgmt/tm/asm/policies/{policy_id}"
                },
            },
        )
        task_id = task_resp.get("id")
        if not task_id:
            raise ExportError(f"No task ID returned for policy {full_path}")

        # Step 2 – poll for completion
        status, result = self._poll_task(task_id, full_path)
        if status != "COMPLETED":
            raise ExportError(
                f"Export task for {full_path} ended with status '{status}'"
            )

        # Step 3 – download
        reported_filename = result.get("filename", filename)
        expected_size: Optional[int] = result.get("fileSize")
        local_path = self.export_dir / reported_filename
        dl_path = f"{self._DOWNLOAD_BASE_EP}/{reported_filename}"
        self.log.info("Downloading: %s → %s", reported_filename, local_path)
        written = self.client.download_file(dl_path, str(local_path), expected_size=expected_size)

        # Validate size
        if expected_size and written != expected_size:
            self.log.warning(
                "Size mismatch for %s: expected %d bytes, got %d bytes.",
                reported_filename, expected_size, written
            )

        self.log.info("Policy exported: %s (%d bytes)", local_path.name, written)
        return local_path

    def _poll_task(self, task_id: str, label: str) -> Tuple[str, Dict]:
        """
        Poll the export-policy task endpoint until COMPLETED or FAILURE.

        Returns (status_string, result_dict).
        """
        deadline = time.monotonic() + _POLL_TIMEOUT
        poll_url = f"{self._EXPORT_TASK_EP}/{task_id}"

        while time.monotonic() < deadline:
            try:
                data = self.client.get(poll_url)
            except Exception as exc:
                self.log.warning("Poll error for task %s: %s", task_id, exc)
                time.sleep(_POLL_INTERVAL)
                continue

            status = data.get("status", "").upper()
            if status in ("COMPLETED", "FAILURE"):
                return status, data.get("result", data)

            self.log.debug("Task %s for %s: status=%s", task_id, label, status)
            time.sleep(_POLL_INTERVAL)

        raise ExportError(
            f"Export task {task_id} for {label} timed out after {_POLL_TIMEOUT}s"
        )
