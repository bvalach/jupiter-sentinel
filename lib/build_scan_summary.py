"""
Sentinel deterministic scan summarizer.

Transforms raw scanner artifacts into:
- scan-summary.json: compact, model-friendly evidence
"""

from __future__ import annotations

import json
import os
import platform
import re
import socket
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    "coverage",
    ".next",
}

TEXT_EXTENSIONS = {
    ".env",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
    ".js",
    ".jsx",
    ".conf",
}

SECRET_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "generic_secret_assignment",
        re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{8,}"),
    ),
    (
        "connection_string_with_password",
        re.compile(r"(?i)(postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^ \n:@]+:[^ \n@]+@"),
    ),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----")),
]

SSH_BASELINE = {
    "permitrootlogin": {"no", "prohibit-password"},
    "passwordauthentication": {"no"},
    "x11forwarding": {"no"},
}


def resolve_path(raw_path: str, base_dir: Path) -> Path:
    if not raw_path:
        return base_dir
    path = Path(raw_path)
    return path if path.is_absolute() else base_dir / path


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def parse_statuses(path: Path) -> List[dict]:
    rows = []
    if not path.exists():
        return rows
    for idx, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines()):
        if idx == 0 or not line.strip():
            continue
        parts = line.split("\t")
        while len(parts) < 4:
            parts.append("")
        rows.append(
            {
                "check": parts[0],
                "status": parts[1],
                "artifact": parts[2],
                "note": parts[3],
            }
        )
    return rows


def parse_upgradable_packages(path: Path) -> List[str]:
    packages = []
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.lower().startswith("listing"):
            continue
        packages.append(line)
    return packages


def parse_brew_outdated(path: Path) -> List[str]:
    payload = read_json(path)
    if not payload:
        return []
    formulae = payload.get("formulae", [])
    casks = payload.get("casks", [])
    names = [item.get("name", "") for item in formulae] + [item.get("name", "") for item in casks]
    return [name for name in names if name]


def parse_cves(path: Path) -> List[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", read_text(path))))


def parse_failed_logins(path: Path) -> dict:
    text = read_text(path)
    lines = [line for line in text.splitlines() if line.strip()]
    ip_hits = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text)
    user_hits = re.findall(r"for (?:invalid user )?([A-Za-z0-9_.-]+)", text, flags=re.IGNORECASE)
    return {
        "count": len(lines),
        "unique_ips": sorted(set(ip_hits))[:20],
        "sample_usernames": sorted(set(user_hits))[:10],
    }


def parse_open_ports(path: Path) -> List[dict]:
    listeners = []
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("COMMAND"):
            parts = re.split(r"\s+", line)
            if len(parts) < 9:
                continue
            local_field = parts[8]
            address, port = split_address_port(local_field)
            listeners.append(
                {
                    "proto": parts[7].lower(),
                    "address": address,
                    "port": port,
                    "process": parts[0],
                }
            )
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        proto = parts[0].lower()
        local_field = parts[4]
        process = parts[6] if len(parts) > 6 else ""
        address, port = split_address_port(local_field)
        listeners.append(
            {
                "proto": proto,
                "address": address,
                "port": port,
                "process": process,
            }
        )
    return listeners


def split_address_port(value: str) -> Tuple[str, str]:
    value = value.strip()
    if not value:
        return "", ""
    if value.startswith("[") and "]:" in value:
        host, port = value.rsplit("]:", 1)
        return host.strip("[]"), port
    if ":" in value:
        host, port = value.rsplit(":", 1)
        return host or "*", port
    return value, ""


def parse_integrity_changes(path: Path) -> List[str]:
    changed = []
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("---") or line.startswith("+++") or line.startswith("@@"):
            continue
        if line.startswith("< ") or line.startswith("> "):
            changed.append(line.split()[-1])
    return sorted(set(changed))


def parse_root_processes(path: Path) -> List[str]:
    rows = []
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("USER "):
            continue
        rows.append(" ".join(line.split()[10:]) or line)
    return rows


def parse_world_writable(path: Path) -> List[str]:
    return [line.strip() for line in read_text(path).splitlines() if line.strip()]


def parse_sshd_settings(raw_dir: Path) -> Dict[str, str]:
    settings = {}
    for candidate in ("sshd-effective.txt", "sshd-config.txt"):
        path = raw_dir / candidate
        if not path.exists():
            continue
        for line in read_text(path).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key = parts[0].lower()
            value = parts[1].strip().lower()
            if key in {
                "permitrootlogin",
                "passwordauthentication",
                "maxauthtries",
                "x11forwarding",
                "allowtcpforwarding",
            }:
                settings[key] = value
    return settings


def audit_ssh(settings: Dict[str, str]) -> List[str]:
    gaps = []
    for key, allowed in SSH_BASELINE.items():
        current = settings.get(key)
        if current and current not in allowed:
            gaps.append(f"{key}={current}")
    max_auth_tries = settings.get("maxauthtries")
    if max_auth_tries:
        try:
            if int(max_auth_tries) > 4:
                gaps.append(f"maxauthtries={max_auth_tries}")
        except ValueError:
            gaps.append(f"maxauthtries={max_auth_tries}")
    return gaps


def parse_docker_inspect(path: Path) -> Tuple[List[dict], List[dict]]:
    payload = read_json(path)
    containers = []
    high_risk = []
    if not isinstance(payload, list):
        return containers, high_risk
    for item in payload:
        mounts = item.get("Mounts", []) or []
        sensitive_mounts = []
        for mount in mounts:
            destination = mount.get("Destination", "")
            source = mount.get("Source", "")
            if destination in {"/", "/etc", "/var/run/docker.sock"} or source in {"/", "/etc", "/var/run/docker.sock"}:
                sensitive_mounts.append(f"{source}:{destination}")
        image = item.get("Config", {}).get("Image", "")
        uses_latest_tag = image.endswith(":latest") or ":" not in image
        container = {
            "name": item.get("Name", "").lstrip("/"),
            "image": image,
            "privileged": bool(item.get("HostConfig", {}).get("Privileged")),
            "network_mode": item.get("HostConfig", {}).get("NetworkMode", ""),
            "uses_latest_tag": uses_latest_tag,
            "sensitive_mounts": sensitive_mounts,
        }
        containers.append(container)
        if container["privileged"] or container["network_mode"] == "host" or sensitive_mounts or uses_latest_tag:
            high_risk.append(container)
    return containers, high_risk


def iter_project_files(paths: Iterable[Path], max_bytes: int) -> Iterable[Path]:
    for root in paths:
        if not root.exists():
            continue
        if root.is_file():
            yield root
            continue
        for current_root, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            base = Path(current_root)
            for file_name in files:
                file_path = base / file_name
                if file_path.suffix.lower() in TEXT_EXTENSIONS or file_name.startswith(".env"):
                    try:
                        if file_path.stat().st_size <= max_bytes:
                            yield file_path
                    except OSError:
                        continue


def mode_string(path: Path) -> str:
    try:
        return oct(stat.S_IMODE(path.stat().st_mode))
    except OSError:
        return "unknown"


def collect_project_inventory(base_dir: Path) -> dict:
    raw_paths = os.environ.get("PROJECT_PATHS", "")
    max_bytes = int(os.environ.get("PROJECT_SCAN_MAX_FILE_BYTES", "1048576"))
    max_matches = int(os.environ.get("MAX_SECRET_MATCHES", "50"))
    project_paths = [resolve_path(item.strip(), base_dir) for item in raw_paths.split(",") if item.strip()]

    env_files = []
    weak_env_files = []
    manifests = []
    secret_matches = []

    for file_path in iter_project_files(project_paths, max_bytes):
        relative_path = str(file_path)
        name = file_path.name.lower()
        if name.startswith(".env"):
            env_files.append({"path": relative_path, "mode": mode_string(file_path)})
            try:
                if stat.S_IMODE(file_path.stat().st_mode) & 0o077:
                    weak_env_files.append(relative_path)
            except OSError:
                pass
        if name in {"package.json", "package-lock.json", "requirements.txt", "pyproject.toml"}:
            manifests.append(relative_path)
        if len(secret_matches) >= max_matches:
            continue
        try:
            with file_path.open("r", encoding="utf-8", errors="replace") as fh:
                for line_number, line in enumerate(fh, start=1):
                    if len(secret_matches) >= max_matches:
                        break
                    for pattern_name, pattern in SECRET_PATTERNS:
                        if pattern.search(line):
                            secret_matches.append(
                                {
                                    "file": relative_path,
                                    "line": line_number,
                                    "pattern": pattern_name,
                                }
                            )
                            break
        except OSError:
            continue

    return {
        "paths": [str(path) for path in project_paths],
        "manifest_count": len(manifests),
        "manifests": manifests[:50],
        "env_files": env_files[:50],
        "weak_env_files": weak_env_files[:20],
        "secret_pattern_matches": secret_matches,
    }


def preliminary_findings(summary: dict) -> List[dict]:
    findings = []

    def add(severity: str, category: str, title: str, description: str, evidence: str, recommendation: str) -> None:
        findings.append(
            {
                "id": f"SCAN-{len(findings) + 1:03d}",
                "severity": severity,
                "category": category,
                "title": title,
                "description": description,
                "evidence": evidence,
                "recommendation": recommendation,
                "package_or_system": None,
                "cve_id": None,
                "source_url": None,
                "requires_action": severity in {"critical", "high", "medium"},
            }
        )

    packages = summary["local_signals"]["packages"]
    auth = summary["local_signals"]["auth"]
    integrity = summary["local_signals"]["integrity"]
    network = summary["local_signals"]["network"]
    permissions = summary["local_signals"]["permissions"]
    docker = summary["local_signals"]["docker"]
    ssh = summary["local_signals"]["ssh"]
    project_inventory = summary["local_signals"]["project_inventory"]

    if packages["debsecan_cves"]:
        add(
            "high",
            "dependency",
            "Local package CVEs detected",
            "The deterministic scan found locally relevant CVE identifiers via the package scanner.",
            ", ".join(packages["debsecan_cves"][:8]),
            "Review the affected packages and confirm remediation before the next daily run.",
        )

    if packages["upgradable_count"] > 0:
        add(
            "medium",
            "dependency",
            "Pending package updates",
            "The host has pending package updates. Some may be security-relevant.",
            f"{packages['upgradable_count']} packages pending update",
            "Review the package backlog and prioritize security updates.",
        )

    if auth["count"] >= 20:
        add(
            "medium",
            "brute-force",
            "Repeated failed login activity",
            "Authentication failures were observed in the last 24 hours.",
            f"{auth['count']} failed logins from up to {len(auth['unique_ips'])} IPs",
            "Check whether exposed services need rate limiting, IP filtering, or stronger SSH posture.",
        )

    if integrity["changed_files"]:
        add(
            "high",
            "integrity",
            "Tracked file integrity drift",
            "One or more tracked files changed compared with the previous checksum baseline.",
            ", ".join(integrity["changed_files"][:6]),
            "Confirm whether the change was expected and refresh the baseline only after validation.",
        )

    if permissions["world_writable_count"] > 0:
        add(
            "medium",
            "permissions",
            "World-writable files in sensitive paths",
            "The scan found world-writable files in paths that are usually security-relevant.",
            f"{permissions['world_writable_count']} files",
            "Review and tighten filesystem permissions for the affected files.",
        )

    if project_inventory["secret_pattern_matches"]:
        add(
            "high",
            "credentials",
            "Potential secrets in scanned project paths",
            "Regex-based scanning found credential-like patterns in project files.",
            f"{len(project_inventory['secret_pattern_matches'])} pattern matches",
            "Verify whether the matches are real secrets and move them to a secure secret store if needed.",
        )

    if project_inventory["weak_env_files"]:
        add(
            "medium",
            "permissions",
            "Environment files with broad permissions",
            "Some .env files are readable by group or other users.",
            ", ".join(project_inventory["weak_env_files"][:6]),
            "Restrict file permissions, ideally to owner-only access.",
        )

    if docker["high_risk_containers"]:
        add(
            "high",
            "docker",
            "High-risk Docker posture detected",
            "One or more containers use privileged mode, host networking, sensitive mounts, or unpinned tags.",
            f"{len(docker['high_risk_containers'])} containers flagged",
            "Reduce container privileges, pin image tags, and review host-level mounts.",
        )

    if ssh["cis_gaps"]:
        add(
            "high",
            "ssh",
            "SSH baseline gaps detected",
            "The effective SSH configuration diverges from a conservative baseline.",
            ", ".join(ssh["cis_gaps"]),
            "Harden the SSH configuration and validate it before restarting the daemon.",
        )

    if network["public_listener_count"] > 0:
        add(
            "medium",
            "network",
            "Public-facing listeners detected",
            "One or more services are listening on all interfaces or a public address.",
            f"{network['public_listener_count']} listeners",
            "Confirm that every public listener is intentional and covered by firewall policy.",
        )

    if not findings:
        add(
            "info",
            "config",
            "No deterministic issues triggered",
            "The deterministic scanner did not trigger any heuristic findings.",
            "No scanner rule exceeded its threshold.",
            "Still review AI findings and raw artifacts before assuming the host is clean.",
        )

    return findings


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: build_scan_summary.py <audit-output-dir>", file=sys.stderr)
        return 1

    out_dir = Path(sys.argv[1]).resolve()
    raw_dir = out_dir / "raw"
    base_dir = Path(os.environ.get("SENTINEL_HOME", out_dir.parent.parent)).resolve()
    statuses = parse_statuses(out_dir / "command-status.tsv")

    upgradable_packages = parse_upgradable_packages(raw_dir / "apt-upgradable.txt")
    brew_outdated = parse_brew_outdated(raw_dir / "brew-outdated.json")
    debsecan_cves = parse_cves(raw_dir / "debsecan.txt")
    listeners = parse_open_ports(raw_dir / "open-ports.txt")
    auth = parse_failed_logins(raw_dir / "failed-logins.txt")
    integrity_changes = parse_integrity_changes(raw_dir / "integrity-diff.txt")
    root_processes = parse_root_processes(raw_dir / "root-processes.txt")
    world_writable = parse_world_writable(raw_dir / "world-writable.txt")
    ssh_settings = parse_sshd_settings(raw_dir)
    ssh_gaps = audit_ssh(ssh_settings)
    docker_containers, docker_high_risk = parse_docker_inspect(raw_dir / "docker-inspect.json")
    project_inventory = collect_project_inventory(base_dir)

    public_listeners = [
        item
        for item in listeners
        if item["address"] in {"0.0.0.0", "::", "*"} or item["address"].startswith("[::")
    ]

    command_failures = [
        row for row in statuses if row["status"].startswith("error") or row["status"] == "skipped"
    ]

    package_names = []
    for line in upgradable_packages:
        package_names.append(line.split("/")[0].split()[0])
    package_names.extend(brew_outdated)

    summary = {
        "date": datetime.now().strftime("%Y-%m-%d"),
        "hostname": os.environ.get("HOSTNAME_LABEL", socket.gethostname()),
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "os": platform.system().lower(),
        "command_status": statuses,
        "blind_spots": command_failures[:30],
        "local_signals": {
            "packages": {
                "upgradable_count": len(upgradable_packages) + len(brew_outdated),
                "upgradable_packages": upgradable_packages[:30] + brew_outdated[:30],
                "relevant_packages": sorted(set(package_names))[:50],
                "debsecan_cves": debsecan_cves[:30],
                "network_audits_enabled": os.environ.get("RUN_NETWORK_AUDITS", "false"),
            },
            "auth": auth,
            "integrity": {
                "changed_files": integrity_changes[:20],
                "baseline_compared": bool(integrity_changes or (raw_dir / "integrity-diff.txt").exists()),
            },
            "network": {
                "listener_count": len(listeners),
                "public_listener_count": len(public_listeners),
                "listeners": listeners[:30],
                "public_listeners": public_listeners[:20],
                "firewall_artifact_present": (raw_dir / "firewall.txt").exists(),
            },
            "permissions": {
                "suid_sgid_count": len(read_text(raw_dir / "suid-sgid.txt").splitlines()),
                "world_writable_count": len(world_writable),
                "world_writable_sample": world_writable[:20],
            },
            "processes": {
                "root_process_count": len(root_processes),
                "root_process_sample": root_processes[:20],
            },
            "docker": {
                "container_count": len(docker_containers),
                "containers": docker_containers[:20],
                "high_risk_containers": docker_high_risk[:20],
            },
            "ssh": {
                "effective_settings": ssh_settings,
                "cis_gaps": ssh_gaps,
            },
            "cron": {
                "user_crontab_present": (raw_dir / "crontab-user.txt").exists(),
                "system_cron_entries": [line.strip() for line in read_text(raw_dir / "cron-system.txt").splitlines() if line.strip()][:50],
            },
            "project_inventory": project_inventory,
        },
    }

    summary["preliminary_findings"] = preliminary_findings(summary)
    output_path = out_dir / "scan-summary.json"
    output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"[summary] wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
