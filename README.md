# mtcompare

Compare the *base* configuration (bridge/VLAN/IGMP settings, switch-chip and
hardware QoS, software queues, SNMP, services, users, NTP, logging, firewall …)
across a fleet of MikroTik RouterOS switches and show only what differs.

Port-level sections are left out unless you ask for them with `--with-ports`.

## Requirements

* Python 3.11+ and `requests` (already installed on this machine)
* REST transport: RouterOS 7.1+ with the `www-ssl` (or `www`) service enabled
  (`/ip/service`), and a user with at least `read` + `rest-api` policy.
* SSH transport: `ssh` on this machine and a key accepted by the switch
  (`/user/ssh-keys`). The tool runs `/export terse` once per device.

## Quick start

```bash
cd ~/mtcompare
cp devices.example.toml devices.toml   # put your subnet(s) or hosts in
export MT_PASSWORD='...'
./mtcompare.py -i devices.toml --discover   # check what the scan finds
./mtcompare.py -i devices.toml
```

Devices come from `[[subnets]]` scans (CIDR, `a-b` range or host list, with
`exclude`), from explicit `[[devices]]` entries, or both. A scan probes the
REST/SSH port of every address in parallel and asks each responder for its
RouterOS identity, which becomes the device name (duplicates get `@ip`
appended). `--discover` prints the result as `[[devices]]` TOML if you would
rather freeze the list. Fetching runs in parallel (`-j`, default 16).

With up to 6 devices you get a side-by-side table; above that the output is
*grouped*: one line per differing field, listing which devices hold which
value, with the majority (or `--baseline`) value first:

```
== /interface/bridge   (1 of 1 items differ)
 * bridge / igmp-snooping
     yes    87  majority (87 devices)
     no      3           sw-45, sw-62, sw-71
```

Force either view with `--format table` / `--format grouped`. Table output:

```
== /interface/bridge   (1 of 1 items differ)
   item    field           sw-core-1  sw-core-2  sw-access-7
 * bridge  igmp-snooping   yes        yes        no
 * bridge  vlan-filtering  yes        no         yes
```

Cell legend: `<absent>` item does not exist on that device (shown once as an
`(exists)` row; fields are then only compared among devices that have the
item), `·` item exists but the field is not set, `n/a` the whole menu is
unavailable on that device/model (e.g. hardware QoS on a non-CRS3xx switch),
`""` empty value.

## Useful options

| option | effect |
|---|---|
| `--baseline NAME` | put that device in the first column |
| `-d NAME -d NAME` | only compare these devices from the inventory |
| `--paths /interface/bridge /snmp` | compare only these menus |
| `--add-paths /ip/address` | add menus to the default list |
| `--with-ports` | also compare `/interface/ethernet`, `/interface/bridge/port`, switch port QoS … |
| `--all` | show identical rows too |
| `--ignore comment` | ignore extra field names |
| `--include-dynamic` | keep dynamic entries (normally skipped) |
| `--format table|grouped|md|json|html` | force an output format |
| `-o FILE` | write the output to a file |
| `--serve [HOST:PORT]` | run the web GUI |
| `--discover` | run the subnet scan, print found devices as TOML, exit |
| `-j 32` | parallel fetch/scan workers |
| `--width 0` | do not truncate long values |
| `--transport ssh` | force SSH for every device |
| `--save DIR` | store raw per-device JSON snapshots |
| `--load DIR` | compare from snapshots instead of live devices |
| `--list-paths` | print the default menu list |

Exit code is `0` when everything matches, `1` when differences were found and
`2` when a device could not be fetched, so it works in cron or CI.

## HTML report and web GUI

```bash
./mtcompare.py -i devices.toml --format html -o drift-$(date +%F).html
```

Writes a single self-contained HTML file (open it in any browser, mail it,
drop it on a share). It has a device rail sorted by how many rows each
switch deviates on, drift sections with the reference value first and the
odd devices out as clickable chips, a text filter, a reference selector
(majority or any device) and a toggle for identical rows. Click a device to
see only where it deviates.

```bash
./mtcompare.py -i devices.toml --serve            # http://127.0.0.1:8765/
./mtcompare.py -i devices.toml --serve 0.0.0.0:8080
```

Starts the same page as a local web GUI with a run bar: "Discover only"
lists what the subnet scan finds, "Run comparison" fetches and compares, a
log shows progress, and the report fills in when it finishes. The paths
filter and "include port menus" apply per run; everything else (inventory,
password, transport, ignore rules) comes from the command line and TOML as
usual. The server binds to localhost by default and has no authentication,
so only expose it on a trusted network.

## Snapshots / drift over time

```bash
./mtcompare.py -i devices.toml --save snapshots/$(date +%F)
# later …
./mtcompare.py --load snapshots/2026-10-01 --load snapshots/2026-10-13
```

Each device becomes `name@date` so you can see what changed on which switch.
Snapshots store the raw API output, so ignore rules and item keys from the
inventory still apply when you load them.

## Notes

* Compare devices using the **same transport**. REST returns every property
  (including defaults); an SSH export contains only non-default values, so
  mixing the two produces lots of spurious `·` rows.
* Runtime/per-device fields (`.id`, MAC addresses, NTP sync state, firewall
  counters, cloud address, …) are ignored by default; see `DEFAULT_IGNORE_FIELDS`
  in the script and the `[sections]` / `[ignore_by_path]` tables in the
  inventory to tune this.
* List items are matched across devices by `name`, or by the per-path keys in
  `DEFAULT_ITEM_KEYS` (e.g. bridge VLANs by `bridge` + `vlan-ids`, firewall
  rules by `chain` + `comment`). Rules without comments fall back to position
  within their chain, so comment your firewall rules for stable matching.
