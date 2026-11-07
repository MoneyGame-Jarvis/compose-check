#!/usr/bin/env python3
"""compose-check — find the settings in a docker-compose.yml that turn a
hobby stack into an incident.

Reads a Compose file (v2 or v3, single file or multi-file) and reports
the risks, with a severity for each and a one-line explanation of why
it matters. No dependencies, no telemetry, nothing leaves the machine.

    python3 compose_check.py docker-compose.yml
    python3 compose_check.py -f docker-compose.yml -f docker-compose.prod.yml
    python3 compose_check.py --format json docker-compose.yml

Exit code 1 when something is found, 0 when it is clean, 2 on a parse
error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

try:
    from miniyaml import loads as _mini_loads
except Exception:  # pragma: no cover
    _mini_loads = None

SEVERITIES = ("critical", "high", "medium", "low")

DANGEROUS_CAPS = {
    "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO", "SYS_BOOT",
    "NET_ADMIN", "NET_RAW", "DAC_READ_SEARCH", "DAC_OVERRIDE", "SETUID",
    "SETGID", "MKNOD", "ALL",
}

SENSITIVE_PATHS = (
    "/", "/etc", "/root", "/home", "/var/run", "/run", "/proc", "/sys",
    "/boot", "/dev", "/usr", "/bin", "/sbin", "/lib",
)

SECRET_HINTS = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"credential|auth)", re.I)

SECRET_VALUE = re.compile(r"^(?!$)(?!\$\{).{3,}$")


class Finding:
    def __init__(self, severity, check, service, message, fix):
        self.severity = severity
        self.check = check
        self.service = service
        self.message = message
        self.fix = fix

    def as_dict(self):
        return {
            "severity": self.severity, "check": self.check,
            "service": self.service, "message": self.message, "fix": self.fix,
        }

    def __str__(self):
        return (f"[{self.severity.upper():8}] {self.service or '(file)'}: "
                f"{self.message}\n           -> {self.fix}")


def _services(doc):
    if not isinstance(doc, dict):
        return {}
    svcs = doc.get("services")
    if isinstance(svcs, dict):
        return svcs
    # Compose v1 used a top-level list of services.
    if isinstance(doc.get("service"), dict):
        return {k: v for k, v in doc.items()
                if isinstance(v, dict) and k not in
                ("version", "networks", "volumes", "configs", "secrets")}
    return {}


def check_service(name, svc, findings):
    if not isinstance(svc, dict):
        return

    if svc.get("privileged") is True:
        findings.append(Finding(
            "critical", "privileged", name,
            "runs privileged, which disables most container isolation",
            "drop `privileged: true` and add only the capabilities you need"))

    net = svc.get("network_mode")
    if net == "host":
        findings.append(Finding(
            "critical", "host-network", name,
            "shares the host network namespace",
            "use a bridge network and publish only the ports you need"))

    for cap in (svc.get("cap_add") or []):
        if str(cap).upper() in DANGEROUS_CAPS:
            findings.append(Finding(
                "high", "capabilities", name,
                f"adds the {cap} capability, which is close to root",
                "drop the capability; almost nothing needs SYS_ADMIN or NET_ADMIN"))

    for mount in (svc.get("volumes") or []):
        if isinstance(mount, str):
            source = mount.split(":")[0]
        elif isinstance(mount, dict):
            source = str(mount.get("source") or "")
        else:
            continue
        if "docker.sock" in source:
            findings.append(Finding(
                "critical", "docker-socket", name,
                "mounts the Docker socket, which is root on the host",
                "remove it, or use a socket proxy with a read-only API subset"))
        for bad in SENSITIVE_PATHS:
            if source == bad or source.startswith(bad.rstrip("/") + "/"):
                findings.append(Finding(
                    "high", "host-mount", name,
                    f"mounts the host path {source}",
                    "mount a specific subdirectory, or a named volume"))
                break

    if svc.get("pid") == "host":
        findings.append(Finding(
            "critical", "host-pid", name,
            "shares the host PID namespace",
            "remove `pid: host`"))

    image = str(svc.get("image") or "")
    if image.endswith(":latest") or (image and ":" not in image.split("/")[-1]):
        findings.append(Finding(
            "medium", "unpinned-image", name,
            f"uses the floating tag {image or '(unset)'}",
            "pin an exact version, or a digest, so a rebuild is reproducible"))

    if not svc.get("healthcheck") and not svc.get("depends_on"):
        findings.append(Finding(
            "low", "no-healthcheck", name,
            "has no healthcheck, so nothing notices it is broken",
            "add a healthcheck and let dependents wait for it"))

    if not svc.get("read_only"):
        findings.append(Finding(
            "medium", "writable-rootfs", name,
            "the root filesystem is writable",
            "set `read_only: true` and mount tmpfs for /tmp"))

    limits = svc.get("deploy", {}).get("resources", {}).get("limits") \
        if isinstance(svc.get("deploy"), dict) else None
    if not limits and not svc.get("mem_limit") and not svc.get("cpus"):
        findings.append(Finding(
            "medium", "no-resource-limits", name,
            "has no memory or CPU limit, so one bug can take the host down",
            "set `mem_limit`/`cpus`, or `deploy.resources.limits`"))

    if not svc.get("user"):
        findings.append(Finding(
            "low", "runs-as-root", name,
            "runs as root inside the container by default",
            "set `user: \"1000:1000\"` or a named non-root user"))

    for key, value in (svc.get("environment") or {}).items():
        if isinstance(value, dict):
            value = value.get("value")
        if not isinstance(value, str):
            continue
        if SECRET_HINTS.search(str(key)) and SECRET_VALUE.match(value):
            if "${" in value:
                continue
            findings.append(Finding(
                "critical", "secret-in-environment", name,
                f"the environment variable {key} holds a literal secret",
                "move it to a secret and reference it with `secrets:`"))

    log = svc.get("logging") or {}
    if isinstance(log, dict):
        opts = log.get("options") or {}
        if log.get("driver") == "json-file" and "max-size" not in opts:
            findings.append(Finding(
                "medium", "unbounded-logs", name,
                "json-file logs with no max-size will fill the disk",
                "set `max-size: 10m` and `max-file: 3`"))

    if svc.get("container_name"):
        findings.append(Finding(
            "low", "container-name", name,
            "sets container_name, which breaks scaling and rolling updates",
            "remove it and let Compose name the containers"))

    for port in (svc.get("ports") or []):
        if isinstance(port, str) and port.startswith("0.0.0.0:"):
            findings.append(Finding(
                "high", "public-port", name,
                f"publishes {port} on every interface",
                "bind to 127.0.0.1 and put a reverse proxy in front"))

    if svc.get("restart") is None:
        findings.append(Finding(
            "low", "no-restart-policy", name,
            "has no restart policy, so it stays down after a crash",
            "set `restart: unless-stopped`"))


def check_file_level(doc, findings):
    if not isinstance(doc, dict):
        return
    nets = doc.get("networks")
    if isinstance(nets, dict):
        for net, cfg in nets.items():
            if isinstance(cfg, dict) and cfg.get("external"):
                continue
            if isinstance(cfg, dict) and not cfg.get("driver"):
                findings.append(Finding(
                    "low", "network-driver", "(file)",
                    f"network {net} does not declare a driver",
                    "set `driver: bridge` explicitly"))
    volumes = doc.get("volumes")
    if isinstance(volumes, dict):
        for vol, cfg in volumes.items():
            if isinstance(cfg, dict) and cfg.get("driver") == "local" \
                    and not cfg.get("driver_opts"):
                findings.append(Finding(
                    "low", "volume-driver-opts", "(file)",
                    f"volume {vol} has no driver_opts, so it cannot be tuned",
                    "set driver_opts with type and device for an SSD or a backup target"))


def load_yaml(text):
    """Parse YAML, preferring PyYAML and falling back to the built-in
    parser so the tool runs with nothing installed."""
    if yaml is not None:
        return yaml.safe_load(text)
    if _mini_loads is None:
        raise SystemExit(
            "compose-check needs a YAML parser: pip install pyyaml, or keep "
            "miniyaml.py next to this file")
    return _mini_loads(text)


def scan(paths):
    doc = {}
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                part = load_yaml(fh.read())
        except FileNotFoundError:
            print(f"compose-check: no such file: {path}", file=sys.stderr)
            raise SystemExit(2)
        except Exception as exc:
            print(f"compose-check: cannot parse {path}: {exc}", file=sys.stderr)
            raise SystemExit(2)
        if not isinstance(part, dict):
            continue
        if "services" in part:
            merged = dict(doc.get("services") or {})
            merged.update(part.get("services") or {})
            doc["services"] = merged
            for key in ("networks", "volumes", "configs", "secrets"):
                if key in part:
                    doc[key] = {**(doc.get(key) or {}), **(part.get(key) or {})}
        else:
            for key, value in part.items():
                if isinstance(value, dict):
                    doc.setdefault("services", {})[key] = value
    return doc


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="compose-check",
        description="Find the risky settings in a docker-compose.yml.")
    ap.add_argument("files", nargs="*", help="compose file(s) to scan")
    ap.add_argument("-f", "--file", action="append", default=[],
                    help="compose file to scan (repeatable)")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--fail-on", choices=SEVERITIES, default="critical",
                    help="lowest severity that makes the exit code non-zero")
    args = ap.parse_args(argv)

    paths = list(args.file) + list(args.files)
    if not paths:
        ap.print_help()
        return 2

    doc = scan(paths)
    findings = []
    for name, svc in _services(doc).items():
        check_service(name, svc, findings)
    check_file_level(doc, findings)

    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f.severity], f.service))

    if args.format == "json":
        print(json.dumps({
            "files": paths,
            "services": sorted(_services(doc)),
            "findings": [f.as_dict() for f in findings],
            "summary": {s: sum(1 for f in findings if f.severity == s)
                        for s in SEVERITIES},
        }, indent=2))
    else:
        print(f"compose-check: {len(paths)} file(s), "
              f"{len(_services(doc))} service(s), {len(findings)} finding(s)")
        for f in findings:
            print(f)
        if findings:
            worst = findings[0].severity
            print(f"\nworst: {worst}")
        else:
            print("\nnothing found. nice.")

    threshold = order[args.fail_on]
    if any(order[f.severity] <= threshold for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
