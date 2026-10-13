#!/usr/bin/env python3
"""
mtcompare - compare base configuration across MikroTik RouterOS switches.

Pulls selected configuration sections from every device in an inventory
(REST API by default, SSH `/export terse` as a fallback), normalises them and
prints a side-by-side table of everything that differs.

Examples:
    mtcompare.py -i devices.toml
    mtcompare.py -i devices.toml --baseline sw-core-1
    mtcompare.py -i devices.toml --paths /interface/bridge /snmp --all
    mtcompare.py -i devices.toml --save snapshots/$(date +%F)
    mtcompare.py --load snapshots/2026-10-01 --load snapshots/2026-10-13
    mtcompare.py -i devices.toml --discover          # list what the [[subnets]] scan finds
    mtcompare.py -i devices.toml --format md > report.md

Exit codes: 0 = no differences, 1 = differences found, 2 = fetch/config error.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import getpass
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

try:
    import requests
    import urllib3
except ImportError:  # pragma: no cover
    requests = None
    urllib3 = None

# --------------------------------------------------------------------------
# Defaults (all overridable from the inventory file or the command line)
# --------------------------------------------------------------------------

# "Base" config sections for a switch: things that should normally be
# identical fleet-wide. Port-level sections are behind --with-ports.
DEFAULT_PATHS = [
    # system
    "/system/routerboard/settings",
    "/system/clock",
    "/system/ntp/client",
    "/system/ntp/client/servers",
    "/system/logging",
    "/system/logging/action",
    "/system/package/update",
    "/system/scheduler",
    "/system/script",
    "/system/watchdog",
    "/system/note",
    # users / management access
    "/user",
    "/user/group",
    "/user/aaa",
    "/user/ssh-keys",
    "/radius",
    "/ip/service",
    "/ip/ssh",
    "/tool/mac-server",
    "/tool/mac-server/mac-winbox",
    "/tool/mac-server/ping",
    "/tool/bandwidth-server",
    "/tool/romon",
    # ip stack
    "/ip/settings",
    "/ip/dns",
    "/ip/dns/static",
    "/ip/neighbor/discovery-settings",
    "/ip/cloud",
    "/ip/proxy",
    "/ip/socks",
    "/ip/traffic-flow",
    "/ip/firewall/connection/tracking",
    "/ip/firewall/filter",
    "/ip/firewall/nat",
    "/ip/firewall/mangle",
    "/ip/firewall/raw",
    "/ip/firewall/service-port",
    "/interface/detect-internet",
    # bridge / switching
    "/interface/bridge",
    "/interface/bridge/settings",
    "/interface/bridge/vlan",
    "/interface/bridge/msti",
    "/interface/bridge/mlag",
    "/interface/bridge/filter",
    "/interface/bridge/nat",
    "/interface/ethernet/switch",
    "/interface/ethernet/switch/rule",
    "/interface/ethernet/switch/l3hw-settings",
    # hardware QoS (CRS3xx/CRS5xx, RouterOS 7.15+) - 404 elsewhere, that's fine
    "/interface/ethernet/switch/qos/profile",
    "/interface/ethernet/switch/qos/map",
    "/interface/ethernet/switch/qos/tx-manager",
    "/interface/ethernet/switch/qos/tx-manager/queue",
    "/interface/ethernet/switch/qos/priority-flow-control",
    # software QoS
    "/queue/type",
    "/queue/simple",
    "/queue/tree",
    # snmp
    "/snmp",
    "/snmp/community",
]

PORT_PATHS = [
    "/interface/ethernet",
    "/interface/bridge/port",
    "/interface/ethernet/switch/port",
    "/interface/ethernet/switch/port-isolation",
    "/interface/ethernet/switch/qos/port",
]

# Runtime / per-device-unique fields that never count as a config difference.
DEFAULT_IGNORE_FIELDS = [
    ".id", ".nextid", "dynamic", "running", "invalid", "inactive", "default",
    "status", "time", "date", "dst-active", "gmt-offset",
    "last-logged-in", "last-link-up-time", "last-link-down-time", "link-downs",
    "actual-mtu", "l2mtu", "mac-address", "current-tagged", "current-untagged",
    "synced-server", "synced-stratum", "system-offset", "freq-drift",
    "last-update-before", "last-update-from", "last-adjustment",
    "installed-version", "latest-version",
    "public-address", "public-address-ipv6", "ddns-name", "warning",
    "cache-used", "dynamic-servers",
    "next-run", "run-count", "last-started",
    "bytes", "packets",
    "serial-number", "model", "firmware", "current-firmware", "upgrade-firmware",
    "system-id",
]

# How to identify an item inside a list section so it can be matched across
# devices. Fallback order when a path is not listed: name, default-name,
# comment, then position.
DEFAULT_ITEM_KEYS = {
    "/interface/bridge/vlan": ["bridge", "vlan-ids"],
    "/interface/bridge/msti": ["bridge", "identifier"],
    "/interface/bridge/port": ["interface"],
    "/interface/bridge/filter": ["chain", "comment"],
    "/interface/bridge/nat": ["chain", "comment"],
    "/ip/firewall/filter": ["chain", "comment"],
    "/ip/firewall/nat": ["chain", "comment"],
    "/ip/firewall/mangle": ["chain", "comment"],
    "/ip/firewall/raw": ["chain", "comment"],
    "/interface/ethernet/switch/rule": ["switch", "comment"],
    "/ip/address": ["address"],
    "/ip/route": ["dst-address", "gateway"],
    "/ip/dns/static": ["name", "regexp", "address"],
    "/system/logging": ["topics", "action"],
    "/system/ntp/client/servers": ["address"],
    "/user/ssh-keys": ["user", "key-owner"],
    "/radius": ["address", "service"],
    "/interface/ethernet": ["default-name"],
}

VERBS = {"add", "set", "remove", "enable", "disable", "move", "comment",
         "reset", "print", "export", "import", "unset"}

_LOG_SINK: list[str] | None = None


def log(msg: str) -> None:
    print(msg, file=sys.stderr)
    if _LOG_SINK is not None:
        _LOG_SINK.append(msg)


# Cell sentinels
NA = object()        # section not available on this device
ABSENT = object()    # item does not exist on this device
MISSING = object()   # item exists, field not present


# --------------------------------------------------------------------------
# Inventory
# --------------------------------------------------------------------------

@dataclass
class Device:
    name: str
    host: str
    transport: str = "rest"          # rest | ssh
    user: str = "admin"
    password: str | None = None
    scheme: str = "https"
    verify_tls: bool = True
    timeout: float = 15.0
    ssh_user: str | None = None
    ssh_key: str | None = None
    ssh_port: int | None = None
    ssh_options: list[str] = field(default_factory=list)
    show_sensitive: bool = False


@dataclass
class Options:
    paths: list[str]
    ignore_fields: set[str]
    ignore_by_path: dict[str, set[str]]
    item_keys: dict[str, list[str]]
    include_dynamic: bool = False


def device_from_cfg(m: dict, args, name: str | None = None, host: str | None = None) -> Device:
    pw = m.get("password")
    if pw is None:
        pw = os.environ.get(m.get("password_env", "MT_PASSWORD"))
    return Device(
        name=name or m["name"], host=host or m["host"],
        transport=args.transport or m.get("transport", "rest"),
        user=m.get("user", "admin"), password=pw,
        scheme=m.get("scheme", "https"),
        verify_tls=bool(m.get("verify_tls", True)) and not args.insecure,
        timeout=float(m.get("timeout", 15)),
        ssh_user=m.get("ssh_user"), ssh_key=m.get("ssh_key"),
        ssh_port=m.get("ssh_port"), ssh_options=list(m.get("ssh_options", [])),
        show_sensitive=bool(m.get("show_sensitive", False)),
    )


def load_inventory(path: Path, args) -> tuple[dict, list[Device], list[dict]]:
    """Returns (config, static devices, subnet scan specs)."""
    with open(path, "rb") as fh:
        cfg = tomllib.load(fh)
    defaults = cfg.get("defaults", {})
    devices: list[Device] = []
    for d in cfg.get("devices", []):
        m = {**defaults, **d}
        if "name" not in m or "host" not in m:
            sys.exit(f"inventory: every [[devices]] entry needs 'name' and 'host': {d}")
        devices.append(device_from_cfg(m, args))
    subnets = []
    for sn in cfg.get("subnets", []):
        m = {**defaults, **sn}
        if not any(k in m for k in ("cidr", "range", "hosts")):
            sys.exit(f"inventory: every [[subnets]] entry needs 'cidr', 'range' or 'hosts': {sn}")
        subnets.append(m)
    return cfg, devices, subnets


# --------------------------------------------------------------------------
# Discovery: scan subnets / ranges for RouterOS devices
# --------------------------------------------------------------------------

def expand_targets(spec: dict) -> list[str]:
    hosts: list[str] = []
    if "cidr" in spec:
        for c in ([spec["cidr"]] if isinstance(spec["cidr"], str) else spec["cidr"]):
            net = ipaddress.ip_network(c, strict=False)
            hosts += [str(h) for h in (net.hosts() if net.num_addresses > 2 else [net.network_address])]
    if "range" in spec:
        for r in ([spec["range"]] if isinstance(spec["range"], str) else spec["range"]):
            a, b = (x.strip() for x in r.split("-", 1))
            start = ipaddress.ip_address(a)
            # allow "10.0.0.10-120" shorthand
            end = ipaddress.ip_address(b) if "." in b or ":" in b else ipaddress.ip_address(
                ".".join(a.split(".")[:3] + [b]))
            hosts += [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
    if "hosts" in spec:
        hosts += list(spec["hosts"])
    excl: set[str] = set()
    for e in spec.get("exclude", []):
        try:
            net = ipaddress.ip_network(e, strict=False)
            excl |= {str(h) for h in net} if net.num_addresses <= 65536 else set()
        except ValueError:
            excl.add(e)
    return [h for h in hosts if h not in excl]


def probe_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def discover_one(spec: dict, host: str, args) -> tuple[str, Device | None, str]:
    """Returns (host, device or None, note)."""
    probe_timeout = float(spec.get("probe_timeout", 1.0))
    transport = args.transport or spec.get("transport", "rest")
    if transport == "rest":
        hostport = host
        port = int(spec.get("port", 0)) or (443 if spec.get("scheme", "https") == "https" else 80)
        if port not in (80, 443):
            hostport = f"{host}:{port}"
        if not probe_port(host, port, probe_timeout):
            return host, None, ""
        dev = device_from_cfg(spec, args, name=host, host=hostport)
        dev.timeout = float(spec.get("identity_timeout", 5))
        try:
            ident = rest_get(dev, "/system/identity")
        except FetchError as e:
            return host, None, f"port {port} open but REST failed: {e}"
        if not isinstance(ident, dict) or "name" not in ident:
            return host, None, f"port {port} open but no RouterOS identity (not a MikroTik?)"
        dev.timeout = float(spec.get("timeout", 15))
        dev.name = ident["name"]
        return host, dev, ""
    else:
        port = int(spec.get("ssh_port") or 22)
        if not probe_port(host, port, probe_timeout):
            return host, None, ""
        dev = device_from_cfg(spec, args, name=host, host=host)
        dev.timeout = float(spec.get("identity_timeout", 5))
        try:
            out = ssh_run(dev, ":put [/system/identity/get name]").strip()
        except FetchError as e:
            return host, None, f"port {port} open but ssh failed: {str(e)[:120]}"
        if not out or "\n" in out:
            return host, None, "port open but did not look like RouterOS"
        dev.timeout = float(spec.get("timeout", 15))
        dev.name = out
        return host, dev, ""


def discover(subnets: list[dict], args, known_hosts: set[str]) -> list[Device]:
    found: list[Device] = []
    notes: list[str] = []
    jobs = []
    for spec in subnets:
        for h in expand_targets(spec):
            if h in known_hosts:
                continue
            jobs.append((spec, h))
    if not jobs:
        return found
    log(f"scanning {len(jobs)} address(es) ...")
    with cf.ThreadPoolExecutor(max_workers=max(args.jobs, 32)) as ex:
        futs = {ex.submit(discover_one, spec, h, args): (spec, h) for spec, h in jobs}
        results = {}
        for f in cf.as_completed(futs):
            host, dev, note = f.result()
            results[host] = dev
            if note:
                notes.append(f"  {host}: {note}")
    # keep scan order, dedupe names
    seen: dict[str, int] = {}
    for _, h in jobs:
        dev = results.get(h)
        if dev is None:
            continue
        if dev.name in seen or dev.name in known_hosts:
            seen[dev.name] = seen.get(dev.name, 1) + 1
            dev.name = f"{dev.name}@{h}"
        else:
            seen[dev.name] = 1
        found.append(dev)
    log(f"discovered {len(found)} RouterOS device(s)")
    for n in notes:
        log(n)
    return found


def build_options(cfg: dict, args) -> Options:
    sec = cfg.get("sections", {})
    if args.paths:
        paths = list(args.paths)
    else:
        paths = list(sec.get("paths", DEFAULT_PATHS))
    if args.with_ports:
        paths += [p for p in PORT_PATHS if p not in paths]
    paths += [p for p in (args.add_paths or []) if p not in paths]
    paths = [normalise_path(p) for p in paths]

    ign = set(DEFAULT_IGNORE_FIELDS)
    ign |= set(sec.get("ignore_fields", []))
    ign |= set(args.ignore or [])
    ign -= set(sec.get("unignore_fields", []))

    ign_by_path = {normalise_path(k): set(v) for k, v in cfg.get("ignore_by_path", {}).items()}
    keys = dict(DEFAULT_ITEM_KEYS)
    keys.update({normalise_path(k): list(v) for k, v in cfg.get("item_keys", {}).items()})
    return Options(paths=paths, ignore_fields=ign, ignore_by_path=ign_by_path,
                   item_keys=keys, include_dynamic=args.include_dynamic)


def normalise_path(p: str) -> str:
    p = p.strip().replace(" ", "/")
    if not p.startswith("/"):
        p = "/" + p
    return re.sub(r"/+", "/", p).rstrip("/")


# --------------------------------------------------------------------------
# Fetching: REST
# --------------------------------------------------------------------------

class FetchError(Exception):
    pass


def rest_get(dev: Device, path: str):
    """GET one menu. Returns list (items), dict (settings) or None (no such menu)."""
    url = f"{dev.scheme}://{dev.host}/rest{path}"
    try:
        r = requests.get(url, auth=(dev.user, dev.password or ""),
                         verify=dev.verify_tls, timeout=dev.timeout)
    except requests.RequestException as e:
        raise FetchError(f"{dev.name}: {url}: {e}") from e
    if r.status_code in (400, 404):
        # RouterOS answers 404 (or 400 "no such command") for menus the
        # device/version does not have.
        return None
    if r.status_code == 401:
        raise FetchError(f"{dev.name}: authentication failed (user '{dev.user}')")
    if r.status_code != 200:
        raise FetchError(f"{dev.name}: {url}: HTTP {r.status_code}: {r.text[:200]}")
    try:
        return r.json()
    except ValueError as e:
        raise FetchError(f"{dev.name}: {url}: invalid JSON") from e


def fetch_rest(dev: Device, paths: list[str]) -> dict:
    if requests is None:
        raise FetchError("python 'requests' module is required for REST transport")
    if not dev.verify_tls and urllib3 is not None:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    info = {}
    res = rest_get(dev, "/system/resource") or {}
    ident = rest_get(dev, "/system/identity") or {}
    info["version"] = res.get("version", "?")
    info["board"] = res.get("board-name", "?")
    info["identity"] = ident.get("name", "?")
    sections = {}
    for p in paths:
        sections[p] = rest_get(dev, p)
    return {"info": info, "sections": sections}


# --------------------------------------------------------------------------
# Fetching: SSH (/export terse)
# --------------------------------------------------------------------------

def ssh_run(dev: Device, command: str) -> str:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={int(dev.timeout)}"]
    if dev.ssh_key:
        cmd += ["-i", os.path.expanduser(dev.ssh_key)]
    if dev.ssh_port:
        cmd += ["-p", str(dev.ssh_port)]
    cmd += dev.ssh_options
    cmd += [f"{dev.ssh_user or dev.user}@{dev.host}", command]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=dev.timeout * 4, check=False)
    except subprocess.TimeoutExpired as e:
        raise FetchError(f"{dev.name}: ssh timed out") from e
    if out.returncode != 0:
        raise FetchError(f"{dev.name}: ssh failed ({out.returncode}): {out.stderr.strip()[:300]}")
    return out.stdout


def parse_export(text: str) -> tuple[dict, dict]:
    """Parse `/export terse` output into {path: list[dict] | dict}."""
    header: dict[str, str] = {}
    sections: dict[str, list | dict] = {}
    pending = ""
    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if pending:
            line = pending + line.strip()
            pending = ""
        if line.rstrip().endswith("\\"):
            pending = line.rstrip()[:-1] + " "
            continue
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            m = re.match(r"#\s*(model|serial number|software id)\s*=\s*(.+)$", s)
            if m:
                header[m.group(1)] = m.group(2).strip()
            m = re.search(r"by RouterOS (\S+)", s)
            if m:
                header["version"] = m.group(1)
            continue
        try:
            toks = shlex.split(s)
        except ValueError:
            toks = s.split()
        if not toks or not toks[0].startswith("/"):
            continue
        parts, i = [], 0
        while i < len(toks) and toks[i] not in VERBS:
            parts.append(toks[i].lstrip("/"))
            i += 1
        if i >= len(toks):
            continue
        path = "/" + "/".join(parts)
        verb = toks[i]
        i += 1
        selector: dict[str, str] = {}
        if verb == "set" and i < len(toks):
            if toks[i] == "[":
                try:
                    j = toks.index("]", i)
                except ValueError:
                    j = len(toks)
                for t in toks[i + 1:j]:
                    if "=" in t:
                        k, v = t.split("=", 1)
                        selector[k] = v
                i = j + 1
            elif "=" not in toks[i]:
                sel = toks[i]
                i += 1
                selector = {"#": sel} if sel.isdigit() else {"name": sel}
        kv: dict[str, str] = {}
        for t in toks[i:]:
            if "=" in t:
                k, v = t.split("=", 1)
                kv[k] = v
            elif t.startswith("!"):
                kv[t[1:]] = ""
            else:
                kv[t] = "yes"
        if verb == "add":
            lst = sections.setdefault(path, [])
            if isinstance(lst, list):
                lst.append(kv)
        elif verb == "set":
            if selector:
                cur = sections.setdefault(path, [])
                if not isinstance(cur, list):
                    continue
                target = None
                if "#" in selector:
                    idx = int(selector["#"])
                    if idx < len(cur):
                        target = cur[idx]
                else:
                    for it in cur:
                        if all(it.get(k) == v for k, v in selector.items()):
                            target = it
                            break
                if target is None:
                    target = {k: v for k, v in selector.items() if k != "#"}
                    cur.append(target)
                target.update(kv)
            else:
                cur = sections.get(path)
                if isinstance(cur, dict):
                    cur.update(kv)
                else:
                    sections[path] = dict(kv)
        # remove/enable/disable/move etc. do not appear in a clean export
    return header, sections


def fetch_ssh(dev: Device, paths: list[str]) -> dict:
    cmd = "/export terse" + (" show-sensitive" if dev.show_sensitive else "")
    text = ssh_run(dev, cmd)
    header, all_sections = parse_export(text)
    ident = all_sections.get("/system/identity")
    info = {
        "version": header.get("version", "?"),
        "board": header.get("model", "?"),
        "identity": ident.get("name", "?") if isinstance(ident, dict) else "?",
    }
    # An export only contains non-default values, so a path that is missing
    # from it simply has nothing configured: treat as empty, not unavailable.
    sections = {p: all_sections.get(p, {}) for p in paths}
    return {"info": info, "sections": sections, "export_only": True}


def fetch(dev: Device, paths: list[str]) -> dict:
    if dev.transport == "rest":
        data = fetch_rest(dev, paths)
    elif dev.transport == "ssh":
        data = fetch_ssh(dev, paths)
    else:
        raise FetchError(f"{dev.name}: unknown transport '{dev.transport}'")
    data["device"] = dev.name
    data["host"] = dev.host
    data["transport"] = dev.transport
    data["fetched"] = dt.datetime.now().isoformat(timespec="seconds")
    return data


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------

def norm_value(v) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    s = str(v)
    if s == "true":
        return "yes"
    if s == "false":
        return "no"
    return s


def truthy(v) -> bool:
    return str(v).lower() in ("true", "yes", "1")


def clean_fields(path: str, item: dict, opts: Options) -> dict:
    drop = opts.ignore_fields | opts.ignore_by_path.get(path, set())
    return {k: norm_value(v) for k, v in item.items() if k not in drop}


def item_key(item: dict, keyfields: list[str] | None, idx: int) -> str:
    if keyfields:
        vals = [str(item[f]) for f in keyfields if item.get(f) not in (None, "")]
        if vals:
            return " / ".join(vals)
    for f in ("name", "default-name", "comment"):
        if item.get(f) not in (None, ""):
            return str(item[f])
    return f"#{idx}"


def normalise_sections(data: dict, opts: Options) -> dict:
    """{path: {item_key: {field: value}}} ; value None means section unavailable."""
    out = {}
    for p in opts.paths:
        raw = data["sections"].get(p)
        if raw is None:
            out[p] = None
            continue
        if isinstance(raw, dict):
            # An export has nothing for this menu: no items, not a settings dict.
            out[p] = {"": clean_fields(p, raw, opts)} if raw else {}
            continue
        items: dict[str, dict] = {}
        keyfields = opts.item_keys.get(p)
        for idx, it in enumerate(raw):
            if not opts.include_dynamic and truthy(it.get("dynamic", "no")):
                continue
            k = item_key(it, keyfields, idx)
            base, n = k, 2
            while k in items:
                k = f"{base} ({n})"
                n += 1
            items[k] = clean_fields(p, it, opts)
        out[p] = items
    return out


# --------------------------------------------------------------------------
# Comparison
# --------------------------------------------------------------------------

def union_ordered(seqs):
    seen, out = set(), []
    for s in seqs:
        for x in s:
            if x not in seen:
                seen.add(x)
                out.append(x)
    return out


def compare(norm: list[dict], paths: list[str]) -> list[dict]:
    report = []
    for p in paths:
        secs = [n.get(p) for n in norm]
        if all(s is None for s in secs):
            report.append({"path": p, "unavailable": [True] * len(secs), "rows": []})
            continue
        keys = union_ordered(s.keys() for s in secs if s is not None)
        rows = []
        for k in keys:
            present = [s is not None and k in s for s in secs]
            if not all(p_ or s is None for p_, s in zip(present, secs)):
                # item missing on some devices: one row for that, and the
                # per-field rows below only compare the devices that have it
                vals = [NA if s is None else ("yes" if k in s else ABSENT) for s in secs]
                rows.append({"item": k, "field": "(exists)", "values": vals, "differs": True})
            fields = union_ordered(sorted(s[k].keys()) for s in secs if s is not None and k in s)
            for f in sorted(fields):
                vals = []
                for s in secs:
                    if s is None:
                        vals.append(NA)
                    elif k not in s:
                        # "" is the settings pseudo-item: an export that has no
                        # line for it just means everything is at defaults.
                        vals.append(MISSING if k == "" else ABSENT)
                    else:
                        vals.append(s[k].get(f, MISSING))
                live = [v for v in vals if v is not ABSENT and v is not NA]
                differs = len({id(v) if v is MISSING else v for v in live}) > 1
                rows.append({"item": k, "field": f, "values": vals, "differs": differs})
        report.append({"path": p, "unavailable": [s is None for s in secs], "rows": rows})
    return report


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

def cell(v, width: int | None) -> str:
    if v is NA:
        s = "n/a"
    elif v is ABSENT:
        s = "<absent>"
    elif v is MISSING:
        s = "·"
    elif v == "":
        s = '""'
    else:
        s = str(v).replace("\n", "\\n")
    if width and len(s) > width:
        s = s[: width - 1] + "…"
    return s


def render_table(report, names, infos, show_all, width, out=sys.stdout):
    def p(*a):
        print(*a, file=out)

    p("Devices:")
    for n, i in zip(names, infos):
        p(f"  {n:<20} {i.get('identity','?'):<20} {i.get('board','?'):<22} RouterOS {i.get('version','?')}"
          + (f"  [{i['transport']}]" if i.get("transport") else ""))
    p()
    n_diff = 0
    n_same = 0
    unavailable_everywhere = []
    for sec in report:
        if all(sec["unavailable"]):
            unavailable_everywhere.append(sec["path"])
            continue
        rows = sec["rows"] if show_all else [r for r in sec["rows"] if r["differs"]]
        d = sum(1 for r in sec["rows"] if r["differs"])
        partial = any(sec["unavailable"])
        if d or partial:
            n_diff += 1
        else:
            n_same += 1
        if not rows and not partial:
            continue
        items = {r["item"] for r in sec["rows"]}
        diff_items = {r["item"] for r in sec["rows"] if r["differs"]}
        p(f"== {sec['path']}   ({len(diff_items)} of {len(items)} items differ)")
        na = [n for n, u in zip(names, sec["unavailable"]) if u]
        if na:
            p(f"   not available on: {', '.join(na)}")
        cols = ["item", "field"] + list(names)
        table = [[r["item"], r["field"]] + [cell(v, width) for v in r["values"]] for r in rows]
        widths = [max(len(c), *(len(row[i]) for row in table)) for i, c in enumerate(cols)]
        p("   " + "  ".join(c.ljust(w) for c, w in zip(cols, widths)))
        for row, r in zip(table, rows):
            mark = "*" if r["differs"] else " "
            p(f" {mark} " + "  ".join(c.ljust(w) for c, w in zip(row, widths)))
        p()
    if unavailable_everywhere:
        p("Not available on any device: " + ", ".join(unavailable_everywhere))
        p()
    p(f"Summary: {n_diff} section(s) differ, {n_same} identical, "
      f"{len(unavailable_everywhere)} unavailable everywhere.")
    return n_diff


def render_md(report, names, infos, show_all, width, out=sys.stdout):
    def p(*a):
        print(*a, file=out)

    p("# MikroTik config comparison")
    p()
    p("| device | identity | board | RouterOS |")
    p("|---|---|---|---|")
    for n, i in zip(names, infos):
        p(f"| {n} | {i.get('identity','?')} | {i.get('board','?')} | {i.get('version','?')} |")
    p()
    n_diff = 0
    for sec in report:
        if all(sec["unavailable"]):
            continue
        rows = sec["rows"] if show_all else [r for r in sec["rows"] if r["differs"]]
        if any(r["differs"] for r in sec["rows"]):
            n_diff += 1
        if not rows:
            continue
        p(f"## `{sec['path']}`")
        na = [n for n, u in zip(names, sec["unavailable"]) if u]
        if na:
            p(f"_not available on: {', '.join(na)}_")
        p()
        p("| item | field | " + " | ".join(names) + " |")
        p("|---|---|" + "---|" * len(names))
        for r in rows:
            vals = [cell(v, width).replace("|", "\\|") for v in r["values"]]
            item = r["item"].replace("|", "\\|")
            if r["differs"]:
                vals = [f"**{v}**" if v != "·" else v for v in vals]
            p(f"| {item} | {r['field']} | " + " | ".join(vals) + " |")
        p()
    p(f"**{n_diff} section(s) differ.**")
    return n_diff


def render_json(report, names, infos, show_all, width, out=sys.stdout):
    def enc(v):
        if v is NA:
            return None
        if v is ABSENT:
            return {"absent": True}
        if v is MISSING:
            return {"missing": True}
        return v

    doc = {"devices": [{"name": n, **i} for n, i in zip(names, infos)], "sections": []}
    n_diff = 0
    for sec in report:
        rows = sec["rows"] if show_all else [r for r in sec["rows"] if r["differs"]]
        if any(r["differs"] for r in sec["rows"]):
            n_diff += 1
        doc["sections"].append({
            "path": sec["path"],
            "unavailable_on": [n for n, u in zip(names, sec["unavailable"]) if u],
            "rows": [{"item": r["item"], "field": r["field"], "differs": r["differs"],
                      "values": dict(zip(names, (enc(v) for v in r["values"])))} for r in rows],
        })
    json.dump(doc, out, indent=2)
    print(file=out)
    return n_diff


def render_grouped(report, names, infos, show_all, width, out=sys.stdout, baseline=None, name_limit=12):
    """Many-device view: one line per differing field, listing which devices hold which value."""
    def p(*a):
        print(*a, file=out)

    # compact device header: count per board / version / transport
    combos: dict[tuple, list[str]] = {}
    for n, i in zip(names, infos):
        combos.setdefault((i.get("board", "?"), i.get("version", "?"), i.get("transport", "")), []).append(n)
    p(f"Devices: {len(names)}")
    for (board, ver, tr), devs in sorted(combos.items(), key=lambda kv: -len(kv[1])):
        p(f"  {len(devs):>3} x {board:<22} RouterOS {ver}" + (f"  [{tr}]" if tr else ""))
    if baseline:
        p(f"  baseline: {baseline}")
    p()

    def namelist(devs):
        if show_all or len(devs) <= name_limit:
            return ", ".join(devs)
        return ", ".join(devs[:name_limit]) + f", … +{len(devs) - name_limit} more"

    n_diff = n_same = 0
    unavailable_everywhere = []
    for sec in report:
        if all(sec["unavailable"]):
            unavailable_everywhere.append(sec["path"])
            continue
        rows = [r for r in sec["rows"] if r["differs"]]
        partial = any(sec["unavailable"])
        if rows or partial:
            n_diff += 1
        else:
            n_same += 1
            continue
        items = {r["item"] for r in sec["rows"]}
        diff_items = {r["item"] for r in rows}
        p(f"== {sec['path']}   ({len(diff_items)} of {len(items)} items differ)")
        na = [n for n, u in zip(names, sec["unavailable"]) if u]
        if na:
            p(f"   not available on: {namelist(na)}")
        for r in rows:
            label = f"{r['item']} / {r['field']}" if r["item"] else r["field"]
            p(f" * {label}")
            groups: dict[str, list[str]] = {}
            for n, v in zip(names, r["values"]):
                if (v is ABSENT and r["field"] != "(exists)") or v is NA:
                    continue  # covered by the "(exists)" row / "not available on" line
                groups.setdefault(cell(v, width), []).append(n)
            vw = max(8, *(len(k) for k in groups))
            ref = None
            if baseline and baseline in names:
                ref = cell(r["values"][names.index(baseline)], width)
                if ref not in groups:
                    ref = max(groups, key=lambda k: len(groups[k]))
            else:
                ref = max(groups, key=lambda k: len(groups[k]))
            order = sorted(groups, key=lambda k: (k != ref, -len(groups[k]), k))
            for val in order:
                devs = groups[val]
                tag = "baseline" if (baseline and val == ref) else ("majority" if val == ref else "")
                shown = f"({len(devs)} devices)" if val == ref and len(devs) > name_limit and not show_all else namelist(devs)
                p(f"     {val:<{vw}}  {len(devs):>3}  {tag:<8} {shown}")
        p()
    if unavailable_everywhere:
        p("Not available on any device: " + ", ".join(unavailable_everywhere))
        p()
    p(f"Summary: {n_diff} section(s) differ, {n_same} identical, "
      f"{len(unavailable_everywhere)} unavailable everywhere.")
    return n_diff


RENDERERS = {"table": render_table, "grouped": render_grouped, "md": render_md, "json": render_json}


# --------------------------------------------------------------------------
# Snapshots
# --------------------------------------------------------------------------

def save_snapshots(datas: list[dict], directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    for d in datas:
        f = directory / f"{d['device']}.json"
        with open(f, "w") as fh:
            json.dump(d, fh, indent=1, sort_keys=True)
    return directory


def load_snapshots(directory: Path, label_with_dir: bool) -> list[dict]:
    out = []
    for f in sorted(directory.glob("*.json")):
        with open(f) as fh:
            d = json.load(fh)
        if label_with_dir:
            d["device"] = f"{d.get('device', f.stem)}@{directory.name}"
        d.setdefault("device", f.stem)
        out.append(d)
    if not out:
        sys.exit(f"no *.json snapshots in {directory}")
    return out


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--inventory", type=Path, help="devices.toml inventory")
    ap.add_argument("-d", "--device", action="append", default=[],
                    help="only these devices from the inventory (repeatable)")
    ap.add_argument("--load", action="append", type=Path, default=[],
                    help="load a snapshot directory as devices instead of/in addition to fetching (repeatable)")
    ap.add_argument("--save", type=Path, help="save fetched raw sections as JSON snapshots into this directory")
    ap.add_argument("--baseline", help="reference device (first column / reference value)")
    ap.add_argument("--paths", nargs="+", help="compare only these menu paths")
    ap.add_argument("--add-paths", nargs="+", help="add these menu paths to the default set")
    ap.add_argument("--with-ports", action="store_true", help="also compare port-level sections")
    ap.add_argument("--ignore", nargs="+", help="extra field names to ignore")
    ap.add_argument("--include-dynamic", action="store_true", help="include dynamic entries")
    ap.add_argument("--all", action="store_true", help="show all rows, not just differing ones")
    ap.add_argument("--format", choices=list(RENDERERS) + ["html"],
                    help="output format (default: table up to 6 devices, grouped above that)")
    ap.add_argument("-o", "--output", type=Path, help="write the report here (html defaults to mtcompare-report.html)")
    ap.add_argument("--serve", nargs="?", const="127.0.0.1:8765", metavar="HOST:PORT",
                    help="start a local web GUI instead of printing (default 127.0.0.1:8765)")
    ap.add_argument("-j", "--jobs", type=int, default=16, help="parallel fetches (default 16)")
    ap.add_argument("--discover", action="store_true",
                    help="scan [[subnets]], print the devices found as TOML [[devices]] entries and exit")
    ap.add_argument("--width", type=int, default=40, help="max cell width for table output (0 = unlimited)")
    ap.add_argument("--transport", choices=["rest", "ssh"], help="override transport for all devices")
    ap.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    ap.add_argument("--ask-password", action="store_true", help="prompt for a password used by devices without one")
    ap.add_argument("--list-paths", action="store_true", help="print the default path list and exit")
    return ap


@dataclass
class Result:
    devices: list[Device]
    datas: list[dict]
    names: list[str]
    infos: list[dict]
    report: list[dict]
    errors: int
    n_diff: int


class PipelineError(Exception):
    pass


def resolve_devices(args, cfg, devices, subnets, password=None) -> list[Device]:
    if password:
        for d in devices:
            if d.password is None:
                d.password = password
        for sn in subnets:
            sn.setdefault("password", password)
    if subnets:
        if urllib3 is not None:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        devices = devices + discover(subnets, args, {d.host.split(":")[0] for d in devices} | {d.name for d in devices})
    if args.device:
        unknown = set(args.device) - {d.name for d in devices}
        if unknown:
            raise PipelineError(f"unknown device(s): {', '.join(sorted(unknown))}")
        devices = [d for d in devices if d.name in args.device]
    return devices


def run_pipeline(args, cfg, devices: list[Device], opts: Options) -> Result:
    """Fetch, load snapshots, normalise and compare. Logs progress via log()."""
    datas: list[dict] = []
    errors = 0
    for dev in devices:
        if dev.transport == "rest" and dev.password is None:
            log(f"warning: {dev.name}: no password (set 'password', MT_PASSWORD or use --ask-password)")

    def _fetch(dev):
        try:
            return dev, fetch(dev, opts.paths), None
        except FetchError as e:
            return dev, None, str(e)

    if devices:
        log(f"fetching {len(devices)} device(s) with {args.jobs} parallel jobs ...")
        with cf.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as ex:
            results = list(ex.map(_fetch, devices))
        for dev, data, err in results:
            if err:
                errors += 1
                log(f"error: {err}")
            else:
                datas.append(data)
        log(f"fetched {len(datas)} device(s), {errors} failed")

    if args.save and datas:
        save_snapshots(datas, args.save)
        log(f"saved {len(datas)} snapshot(s) to {args.save}")

    for d in args.load:
        datas += load_snapshots(d, label_with_dir=len(args.load) > 1 or bool(devices))

    if len(datas) < 2:
        raise PipelineError("need at least two devices to compare" + (f" ({errors} failed)" if errors else ""))

    if args.baseline:
        names = [d["device"] for d in datas]
        if args.baseline not in names:
            raise PipelineError(f"baseline '{args.baseline}' not among: {', '.join(names)}")
        datas.sort(key=lambda d: d["device"] != args.baseline)

    if len({d.get("transport") for d in datas}) > 1:
        log("warning: mixing REST and SSH data; SSH exports only contain non-default "
            "values so many fields will show as unset")

    names = [d["device"] for d in datas]
    infos = [{**d.get("info", {}), "transport": d.get("transport", ""), "host": d.get("host", "")} for d in datas]
    norm = [normalise_sections(d, opts) for d in datas]
    report = compare(norm, opts.paths)
    n_diff = sum(1 for sec in report
                 if (any(r["differs"] for r in sec["rows"]) or any(sec["unavailable"]))
                 and not all(sec["unavailable"]))
    return Result(devices, datas, names, infos, report, errors, n_diff)


# --------------------------------------------------------------------------
# HTML report / web GUI
# --------------------------------------------------------------------------

TEMPLATE = Path(__file__).resolve().parent / "report.html"


def build_doc(res: Result, baseline: str | None) -> dict:
    """Compact JSON document for the HTML report: per row, values -> device indices."""
    def enc(v):
        if v is NA:
            return "\0na"
        if v is ABSENT:
            return "\0absent"
        if v is MISSING:
            return "\0missing"
        return v

    devices = [{"name": n, "identity": i.get("identity", ""), "board": i.get("board", ""),
                "version": i.get("version", ""), "transport": i.get("transport", ""), "host": i.get("host", "")}
               for n, i in zip(res.names, res.infos)]
    sections = []
    for sec in res.report:
        rows = []
        for r in sec["rows"]:
            groups: dict[str, list[int]] = {}
            for idx, v in enumerate(r["values"]):
                if v is NA or (v is ABSENT and r["field"] != "(exists)"):
                    continue
                groups.setdefault(enc(v), []).append(idx)
            rows.append({"item": r["item"], "field": r["field"], "differs": r["differs"],
                         "groups": sorted(([k, v] for k, v in groups.items()), key=lambda g: -len(g[1]))})
        sections.append({"path": sec["path"],
                         "unavailable": [i for i, u in enumerate(sec["unavailable"]) if u],
                         "rows": rows})
    return {"generated": dt.datetime.now().strftime("%Y-%m-%d %H:%M"), "baseline": baseline,
            "devices": devices, "sections": sections}


def render_html(doc: dict | None, serve: bool = False) -> str:
    body = TEMPLATE.read_text(encoding="utf-8")
    data = json.dumps(doc, separators=(",", ":")).replace("</", "<\\/") if doc else "null"
    body = body.replace("__DATA__", data).replace("__SERVE__", "true" if serve else "false")
    return ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            '</head>\n<body>\n' + body + '\n</body>\n</html>\n')


def serve(args, cfg, devices, subnets, opts, password) -> int:
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    host, _, port = args.serve.rpartition(":")
    host, port = (host or "127.0.0.1"), int(port or 8765)
    state = {"running": False, "done": False, "error": None, "log": [], "doc": None,
             "inventory": str(args.inventory or ", ".join(map(str, args.load)))}
    lock = threading.Lock()

    def job(opts_in: dict):
        global _LOG_SINK
        with lock:
            state.update(running=True, done=False, error=None, log=[])
        _LOG_SINK = state["log"]
        try:
            import copy
            a = copy.copy(args)
            a.with_ports = bool(opts_in.get("with_ports"))
            want = [p for p in str(opts_in.get("paths", "")).replace(",", " ").split() if p]
            o = build_options(cfg, a)
            if want:
                o.paths = [p for p in o.paths if any(w.lower() in p.lower() for w in want)] or \
                          [normalise_path(w) for w in want]
            devs = resolve_devices(a, cfg, list(devices), [dict(sn) for sn in subnets], password)
            if opts_in.get("discover"):
                for d in devs:
                    log(f"  {d.name:<28} {d.host}  [{d.transport}]")
                log(f"{len(devs)} device(s) would be compared")
                return
            res = run_pipeline(a, cfg, devs, o)
            with lock:
                state["doc"] = build_doc(res, a.baseline)
            log(f"done: {res.n_diff} menu(s) with drift")
        except (PipelineError, FetchError) as e:
            with lock:
                state["error"] = str(e)
            log(f"error: {e}")
        except Exception as e:  # noqa: BLE001 - surface anything in the GUI
            with lock:
                state["error"] = f"{type(e).__name__}: {e}"
            log(f"error: {type(e).__name__}: {e}")
        finally:
            _LOG_SINK = None
            with lock:
                state.update(running=False, done=True)

    page = render_html(None, serve=True).encode()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _send(self, code, body, ctype="application/json"):
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self._send(200, page, "text/html")
            elif self.path == "/api/status":
                with lock:
                    body = {k: v for k, v in state.items() if k != "doc"}
                    body["has_data"] = state["doc"] is not None
                self._send(200, json.dumps(body).encode())
            elif self.path == "/api/data":
                with lock:
                    doc = state["doc"]
                if doc is None:
                    self._send(404, b'{"error":"no data yet"}')
                else:
                    self._send(200, json.dumps(doc, separators=(",", ":")).encode())
            else:
                self._send(404, b'{"error":"not found"}')

        def do_POST(self):
            if self.path != "/api/run":
                self._send(404, b'{"error":"not found"}')
                return
            n = int(self.headers.get("Content-Length") or 0)
            try:
                opts_in = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                opts_in = {}
            with lock:
                if state["running"]:
                    self._send(409, b'{"error":"already running"}')
                    return
            threading.Thread(target=job, args=(opts_in,), daemon=True).start()
            self._send(202, b'{"started":true}')

    srv = ThreadingHTTPServer((host, port), H)
    url = f"http://{host}:{port}/"
    print(f"mtcompare GUI on {url}  (Ctrl-C to stop)", file=sys.stderr)
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:  # noqa: BLE001
        pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if args.list_paths:
        print("\n".join(DEFAULT_PATHS))
        print("\n# --with-ports adds:")
        print("\n".join(PORT_PATHS))
        return 0

    cfg, devices, subnets = ({}, [], [])
    if args.inventory:
        cfg, devices, subnets = load_inventory(args.inventory, args)
    elif not args.load:
        ap.error("need -i/--inventory and/or --load")

    opts = build_options(cfg, args)
    password = getpass.getpass("RouterOS password: ") if args.ask_password and (devices or subnets) else None

    if args.serve:
        return serve(args, cfg, devices, subnets, opts, password)

    try:
        devices = resolve_devices(args, cfg, devices, subnets, password)
    except PipelineError as e:
        sys.exit(str(e))

    if args.discover:
        for d in devices:
            print(f'[[devices]]\nname = "{d.name}"\nhost = "{d.host}"'
                  + (f'\ntransport = "{d.transport}"' if d.transport != "rest" else "") + "\n")
        return 0

    try:
        res = run_pipeline(args, cfg, devices, opts)
    except PipelineError as e:
        print(str(e), file=sys.stderr)
        return 2

    fmt = args.format or ("table" if len(res.datas) <= 6 else "grouped")
    if fmt == "html":
        out = args.output or Path("mtcompare-report.html")
        out.write_text(render_html(build_doc(res, args.baseline)), encoding="utf-8")
        log(f"report written to {out}  ({res.n_diff} menu(s) with drift)")
    else:
        sink = open(args.output, "w") if args.output else sys.stdout
        try:
            if fmt == "grouped":
                render_grouped(res.report, res.names, res.infos, args.all, args.width or None,
                               out=sink, baseline=args.baseline)
            else:
                RENDERERS[fmt](res.report, res.names, res.infos, args.all, args.width or None, out=sink)
        finally:
            if sink is not sys.stdout:
                sink.close()
    if res.errors:
        return 2
    return 1 if res.n_diff else 0


if __name__ == "__main__":
    sys.exit(main())
