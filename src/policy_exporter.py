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


def _parse_destination(destination: str) -> Tuple[str, str]:
    """
    Parse an F5 LTM virtual server destination string into (ip, port).

    F5 formats:
      /Common/10.1.1.1:80       →  ("10.1.1.1", "80")
      /Common/10.1.1.1:443      →  ("10.1.1.1", "443")
      /Common/2001:db8::1.443   →  ("2001:db8::1", "443")  IPv6 uses dot for port
      10.1.1.1:8080             →  ("10.1.1.1", "8080")
    """
    raw = destination
    # Strip leading partition component: /Common/10.0.0.1:80  →  10.0.0.1:80
    if raw.startswith('/'):
        stripped = raw.strip('/')
        parts = stripped.split('/', 1)
        raw = parts[1] if len(parts) == 2 else parts[0]

    # IPv6: multiple colons — F5 uses a trailing dot before the port
    if raw.count(':') > 1 and '.' in raw:
        last_dot = raw.rfind('.')
        return raw[:last_dot], raw[last_dot + 1:]

    # IPv4 / named address: single colon separates IP and port
    if ':' in raw:
        ip, _, port = raw.rpartition(':')
        return ip, port

    return raw, ""


def _extract_host_conditions(rule: Dict) -> List[str]:
    """
    Extract host-name values from an LTM policy rule's conditions.

    F5 BIG-IP uses several condition types to match the HTTP Host header:
      - httpHeader with name == "host"  (most common, all versions)
      - httpUri   with host == true     (URI component matching)
      - httpHost                        (dedicated type in newer BIG-IP versions)

    Returns a deduplicated, ordered list of host strings.
    """
    hosts: List[str] = []
    for cond in rule.get("conditionsReference", {}).get("items", []):
        ctype = cond.get("type", "").lower()
        if ctype == "httpheader" and cond.get("name", "").lower() == "host":
            hosts.extend(cond.get("values", []))
        elif ctype == "httpuri" and cond.get("host"):
            hosts.extend(cond.get("values", []))
        elif ctype == "httphost":
            hosts.extend(cond.get("values", []))
    # Deduplicate while preserving order
    seen: set = set()
    unique: List[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            unique.append(h)
    return unique


def _extract_waf_policy_action(rule: Dict) -> str:
    """
    Extract the WAF/ASM security policy path from an LTM policy rule's actions.

    F5 uses two action types for WAF association:
      - type "asm"  with a "policy" field        (BIG-IP 12.1+)
      - type "wam"  with a "wamPolicy" / "policy" field  (older versions)

    Returns the full path of the ASM policy (e.g. "/Common/my_waf") or "".
    """
    for action in rule.get("actionsReference", {}).get("items", []):
        atype = action.get("type", "").lower()
        if atype == "asm" and action.get("enable"):
            return action.get("policy", "")
        if atype == "wam" and action.get("enable"):
            return action.get("wamPolicy", "") or action.get("policy", "")
    return ""


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
    _VIRTUAL_EP       = "/mgmt/tm/ltm/virtual"
    _LTM_POLICY_EP    = "/mgmt/tm/ltm/policy"

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

    # ── Virtual server enrichment ──────────────────────────────────────────────

    def enrich_with_virtual_servers(self, policies: List[Dict]) -> None:
        """
        Enrich each policy dict in-place with a ``virtual_servers`` list.

        Each entry in the list is a dict with keys:
          name, fullPath, destination, ip, port

        This is a best-effort operation: individual failures are logged at
        DEBUG level and result in an empty list for the affected policy.
        """
        self.log.info("Fetching virtual server bindings for %d policies …", len(policies))
        for policy in policies:
            policy["virtual_servers"] = self._get_policy_virtual_servers(
                policy.get("id", ""), policy.get("fullPath", "")
            )

    def _get_policy_virtual_servers(self, policy_id: str, policy_path: str) -> List[Dict]:
        """
        Return virtual server details for a single ASM policy.

        Tries the ``/mgmt/tm/asm/policies/{id}/virtual-servers`` sub-collection
        first (works on BIG-IP 12.1+).  Falls back to an empty list on any error.
        """
        if not policy_id:
            return []

        try:
            data = self.client.get(
                f"/mgmt/tm/asm/policies/{policy_id}/virtual-servers"
            )
        except Exception as exc:
            self.log.debug(
                "Could not retrieve virtual-server bindings for %s: %s",
                policy_path, exc,
            )
            return []

        results = []
        for item in data.get("items", []):
            # The sub-collection item may carry the VS path directly as 'name'
            # or as a self-link such as:
            #   https://localhost/mgmt/tm/ltm/virtual/~Common~my_vs?ver=…
            vs_path = item.get("name", "")
            link = item.get("selfLink", "") or item.get("link", "")

            if not vs_path and link:
                try:
                    # Extract /mgmt/tm/ltm/virtual/~Common~my_vs
                    after = link.split("/mgmt/tm/ltm/virtual/")[1].split("?")[0]
                    # Tilde-encoded path → slash-separated path
                    vs_path = "/" + after.replace("~", "/").lstrip("/")
                except (IndexError, AttributeError):
                    self.log.debug("Unparseable VS link for %s: %s", policy_path, link)
                    continue

            if not vs_path:
                continue

            vs_info = self._get_vs_destination(vs_path)
            if vs_info:
                results.append(vs_info)

        return results

    def _get_vs_destination(self, vs_full_path: str) -> Optional[Dict]:
        """
        GET a single LTM virtual server and return its name, fullPath,
        destination, ip, port, and any attached Local Traffic Policies.

        The path is tilde-encoded for the REST URL:
          /Common/my_vs  →  /mgmt/tm/ltm/virtual/~Common~my_vs
        """
        encoded = vs_full_path.strip("/").replace("/", "~")
        api_path = f"{self._VIRTUAL_EP}/~{encoded}"

        try:
            data = self.client.get(
                api_path,
                params={"$select": "name,fullPath,destination,partition"},
            )
        except Exception as exc:
            self.log.debug("Could not fetch VS %s: %s", vs_full_path, exc)
            return None

        destination = data.get("destination", "")
        ip, port = _parse_destination(destination)

        return {
            "name":        data.get("name", ""),
            "fullPath":    data.get("fullPath", vs_full_path),
            "destination": destination,
            "ip":          ip,
            "port":        port,
            "ltm_policies": self._get_vs_ltm_policies(api_path),
        }

    def _get_vs_ltm_policies(self, vs_api_path: str) -> List[Dict]:
        """
        Return the Local Traffic Policies attached to a virtual server.

        Calls GET {vs_api_path}/policies, then for each attached LTM policy
        fetches the full rule/condition/action tree so we can surface
        host-header → WAF-policy mappings.

        Returns a list of dicts, each with:
          name, fullPath, rules
        where each rule has:
          name, host_conditions (list of str), waf_policy (str or "")
        """
        try:
            data = self.client.get(f"{vs_api_path}/policies")
        except Exception as exc:
            self.log.debug("Could not fetch LTM policies for VS %s: %s", vs_api_path, exc)
            return []

        results = []
        for item in data.get("items", []):
            name = item.get("name", "")
            partition = item.get("partition", "Common")
            full_path = item.get("fullPath", f"/{partition}/{name}")
            rules = self._get_ltm_policy_rules(full_path)
            results.append({
                "name":     name,
                "fullPath": full_path,
                "rules":    rules,
            })

        return results

    def _get_ltm_policy_rules(self, policy_full_path: str) -> List[Dict]:
        """
        Fetch an LTM (Local Traffic Policy) with its rules, conditions, and
        actions expanded in a single API call.

        Parses each rule to extract:
          - host_conditions: host names matched by httpHeader/httpUri/httpHost
            conditions (the "selector" for which web application this rule applies to)
          - waf_policy: the ASM/WAF security policy path applied by the rule's
            action (empty string if no ASM action is present)

        Only rules that have at least one host condition or a WAF policy action
        are included in the returned list.

        Returns a list of dicts: {name, host_conditions, waf_policy}
        """
        encoded  = policy_full_path.strip("/").replace("/", "~")
        api_path = f"{self._LTM_POLICY_EP}/~{encoded}"

        try:
            data = self.client.get(api_path, params={"expandSubcollections": "true"})
        except Exception as exc:
            self.log.debug("Could not fetch LTM policy %s: %s", policy_full_path, exc)
            return []

        rules = []
        for rule in data.get("rulesReference", {}).get("items", []):
            host_conditions = _extract_host_conditions(rule)
            waf_policy      = _extract_waf_policy_action(rule)
            if host_conditions or waf_policy:
                rules.append({
                    "name":            rule.get("name", ""),
                    "host_conditions": host_conditions,
                    "waf_policy":      waf_policy,
                })

        return rules

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
        # Strip any directory components from the server-supplied filename to
        # prevent path traversal (e.g. "../../etc/cron.d/evil").
        raw_filename = result.get("filename", filename)
        reported_filename = Path(raw_filename).name or filename
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
