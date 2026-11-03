#!/usr/bin/env python3
"""
ONOS REST helper and flow policy for the sovereign cyber-range PoC slice.

Policy (all rules installed through the ONOS REST API, table 0):
  * ALLOW  (prio 51000)  h1<->h2 IPv4, bound to in_port + src MAC + src IP,
                         Ethernet destination rewritten to the verified peer MAC,
                         and mirrored to h6 (IDS function, Suricata).
  * ALLOW  (prio 51000)  scoped ARP for the authorized pairs only
                         (in_port + src MAC + eth_type=ARP -> peer port only, never FLOOD).
                         NOTE: this ONOS build's REST codec does not support the
                         ARP_SPA/ARP_TPA criterion types ("Type ARP_SPA is unknown"),
                         confirmed by direct REST probing, even though the core
                         Criterion.Type enum has them (an onos-rest codec gap in this
                         build, which also ships org.onosproject.p4tutorial.pipeconf).
                         IN_PORT + ETH_SRC + ETH_TYPE is sufficient here because each
                         flow already hard-codes a single output port per authorized
                         pair -- it is still scoped, still non-flooding, just without
                         the extra IP-level match.
  * ALLOW  (prio 51000)  h1<->h5 TCP/11434 only (orchestrator <-> bounded-AI host).
  * DENY   (prio 49000)  all other ARP and all other IPv4 (above ONOS's 40000 intercepts).
  * DENY   (prio 1)      catch-all.

Standalone use:
  python3 flows.py status | push | clear | show
"""
import argparse
import base64
import json
import time
import urllib.error
import urllib.request

# name: (switch port, IPv4, MAC, role) -- for a single slice (slice index 0).
# ROLE_SPEC is slice-independent; make_hosts(i) derives the per-slice table
# (distinct subnet + MAC range per slice) so N slices can run concurrently
# on independent OVS switches/ONOS devices without any address collision.
ROLE_SPEC = [
    ("h1", 1, "authorized host / orchestrator"),
    ("h2", 2, "authorized peer"),
    ("h3", 3, "on-path attacker"),
    ("h4", 4, "unauthorized destination"),
    ("h5", 5, "bounded-AI host (Ollama)"),
    ("h6", 6, "IDS function (Suricata on mirror)"),
    ("h7", 7, "boundary gateway (stands in for outside)"),
]


def make_hosts(slice_idx):
    """Per-slice host table: slice 0 is byte-identical to the original
    single-slice HOSTS table (10.0.0.x, MAC 00:00:00:00:00:0x), so existing
    single-slice evidence (run_tests.sh) is unaffected. Slice i>0 gets its
    own /24 (10.0.i.x) and its own MAC range (00:00:00:i:00:0x), fully
    independent of every other slice -- no shared broadcast domain, since
    each slice is its own OVS switch/ONOS device.
    """
    h = {}
    for name, port, role in ROLE_SPEC:
        last = 0xFE if name == "h7" else port
        ip = f"10.0.{slice_idx}.{254 if name == 'h7' else port}"
        mac = f"00:00:00:{slice_idx:02x}:00:{last:02x}"
        h[name] = (port, ip, mac, role)
    return h


def dpid_hex(slice_idx):
    return f"{slice_idx + 1:016x}"


def device_id(slice_idx):
    return "of:" + dpid_hex(slice_idx)


# Backward-compatible module-level constants for slice 0 (unchanged values).
HOSTS = make_hosts(0)
DPID = dpid_hex(0)
DEVICE_ID = device_id(0)
REST_APP = "org.onosproject.rest"

PRIO_ALLOW = 51000
PRIO_DENY = 49000
PRIO_SCALE = 30000
PRIO_CATCHALL = 1
AI_PORT = 11434


# ---------------------------------------------------------------- ONOS client
class Onos:
    def __init__(self, url="http://127.0.0.1:8181/onos/v1", user="onos", password="rocks"):
        self.url = url.rstrip("/")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def req(self, method, path, body=None, ignore=()):
        data = json.dumps(body).encode() if body is not None else None
        headers = self.headers if data is not None else {
            k: v for k, v in self.headers.items() if k != "Content-Type"
        }
        r = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                txt = resp.read().decode()
                return json.loads(txt) if txt.strip() else {}
        except urllib.error.HTTPError as e:
            if e.code in ignore:
                return {}
            raise RuntimeError(f"{method} {path} -> HTTP {e.code}: {e.read().decode()[:500]}")

    def get(self, path, **kw):
        return self.req("GET", path, **kw)

    # applications
    def app_state(self, app):
        try:
            return self.get(f"/applications/{app}").get("state", "unknown")
        except RuntimeError:
            return "not installed"

    def activate(self, app):
        self.req("POST", f"/applications/{app}/active", ignore=(404,))

    def deactivate(self, app):
        self.req("DELETE", f"/applications/{app}/active", ignore=(404,))

    # devices
    def device_available(self, dev=DEVICE_ID):
        try:
            return bool(self.get(f"/devices/{dev}").get("available"))
        except Exception:
            return False

    def wait_device(self, dev=DEVICE_ID, timeout=120, want=True):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.device_available(dev) == want:
                return True
            time.sleep(0.5)
        return False

    def all_devices_available(self, n, timeout=60):
        """True once every slice 0..n-1's device has connected to ONOS."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            if all(self.device_available(device_id(i)) for i in range(n)):
                return True
            time.sleep(0.5)
        return False

    # flows
    def rest_flows(self):
        return self.get(f"/flows/application/{REST_APP}", ignore=(404,)).get("flows", [])

    def clear_rest_flows(self):
        """Removes every flow installed through REST (including any old ARP flood rule)."""
        self.req("DELETE", f"/flows/application/{REST_APP}", ignore=(404,))

    def push(self, flows):
        return self.req("POST", "/flows", {"flows": flows})

    def wait_added(self, n, timeout=120):
        t0 = time.time()
        while time.time() - t0 < timeout:
            added = sum(1 for f in self.rest_flows() if f.get("state") == "ADDED")
            if added >= n:
                return True
            time.sleep(0.3)
        return False

    def version(self):
        try:
            return self.get("/system").get("version")
        except Exception:
            return None


# ------------------------------------------------------------- flow builders
def crit(kind, **kw):
    d = {"type": kind}
    d.update(kw)
    return d


def out(port):
    return {"type": "OUTPUT", "port": str(port)}


def set_eth_dst(mac):
    return {"type": "L2MODIFICATION", "subtype": "ETH_DST", "mac": mac}


def drop():
    # Empty instruction list = drop. If your ONOS rejects it, use:
    # return [{"type": "NOACTION"}]
    return []


def flow(dev, prio, criteria, instructions):
    return {
        "priority": prio,
        "timeout": 0,
        "isPermanent": True,
        "deviceId": dev,
        "tableId": 0,
        "selector": {"criteria": criteria},
        "treatment": {"instructions": instructions},
    }


def _src(hosts, a):
    port, ip, mac, _ = hosts[a]
    return [crit("IN_PORT", port=port), crit("ETH_SRC", mac=mac)]


def arp_allow(dev, hosts, a, peers):
    """ARP from a, delivered only to the explicitly listed peer ports (never flooded).

    ARP_SPA/ARP_TPA are omitted: this ONOS build's REST codec rejects them
    ("Type ARP_SPA is unknown"), confirmed independently for both types.
    IN_PORT + ETH_SRC + ETH_TYPE already scopes this to host a's own port/MAC.
    Because the match no longer varies per destination, every authorized peer
    of a must be enumerated as a separate OUTPUT action on ONE flow (not one
    flow per pair) -- otherwise two identical-selector flows for the same a
    collide in ONOS and only the last one installed survives, silently
    breaking ARP for the other peer. Enumerated OUTPUTs keep it non-flooding.
    """
    return flow(dev, PRIO_ALLOW,
                _src(hosts, a) + [crit("ETH_TYPE", ethType="0x0806")],
                [out(hosts[b][0]) for b in peers])


def ipv4_allow(dev, hosts, a, b, mirror_port=None):
    insts = [set_eth_dst(hosts[b][2]), out(hosts[b][0])]
    if mirror_port:
        insts.append(out(mirror_port))
    return flow(dev, PRIO_ALLOW,
                _src(hosts, a) + [crit("ETH_TYPE", ethType="0x0800"),
                                  crit("IPV4_SRC", ip=hosts[a][1] + "/32"),
                                  crit("IPV4_DST", ip=hosts[b][1] + "/32")],
                insts)


def tcp_allow(dev, hosts, a, b, dst_port=None, src_port=None):
    c = _src(hosts, a) + [crit("ETH_TYPE", ethType="0x0800"),
                          crit("IPV4_SRC", ip=hosts[a][1] + "/32"),
                          crit("IPV4_DST", ip=hosts[b][1] + "/32"),
                          crit("IP_PROTO", protocol=6)]
    if dst_port:
        c.append(crit("TCP_DST", tcpPort=dst_port))
    if src_port:
        c.append(crit("TCP_SRC", tcpPort=src_port))
    return flow(dev, PRIO_ALLOW, c, [set_eth_dst(hosts[b][2]), out(hosts[b][0])])


def lab_policy(dev=DEVICE_ID, hosts=None, mirror=True):
    hosts = hosts if hosts is not None else HOSTS
    ids_port = hosts["h6"][0] if mirror else None
    f = []
    for a, b in (("h1", "h2"), ("h2", "h1")):
        f.append(ipv4_allow(dev, hosts, a, b, mirror_port=ids_port))
    # one ARP-allow flow per source host, enumerating every authorized peer
    # (h1 has two authorized ARP peers: h2 and h5; see arp_allow's docstring)
    f.append(arp_allow(dev, hosts, "h1", ["h2", "h5"]))
    f.append(arp_allow(dev, hosts, "h2", ["h1"]))
    f.append(arp_allow(dev, hosts, "h5", ["h1"]))
    f.append(tcp_allow(dev, hosts, "h1", "h5", dst_port=AI_PORT))
    f.append(tcp_allow(dev, hosts, "h5", "h1", src_port=AI_PORT))
    f.append(flow(dev, PRIO_DENY, [crit("ETH_TYPE", ethType="0x0806")], drop()))
    f.append(flow(dev, PRIO_DENY, [crit("ETH_TYPE", ethType="0x0800")], drop()))
    f.append(flow(dev, PRIO_CATCHALL, [], drop()))
    return f


def multi_slice_policy(n_slices, mirror=True):
    """Policy for N independent, concurrently-managed slices in one flow
    list -- one ONOS REST POST provisions every slice's rules at once,
    which is itself part of the evidence for realistic multi-tenant
    cyber-range provisioning (see 90_multislice* in the multi-slice test).
    """
    rules = []
    for i in range(n_slices):
        rules += lab_policy(dev=device_id(i), hosts=make_hosts(i), mirror=mirror)
    return rules


def scale_flows(dev, n, start=0):
    """n synthetic per-slice deny rules (distinct /32 destinations) for the control-plane scaling test."""
    rules = []
    for i in range(start, start + n):
        ip = f"172.16.{i // 250}.{i % 250 + 1}/32"
        rules.append(flow(dev, PRIO_SCALE,
                          [crit("IN_PORT", port=3), crit("ETH_TYPE", ethType="0x0800"),
                           crit("IPV4_DST", ip=ip)],
                          drop()))
    return rules


# ------------------------------------------------------------------- CLI
if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cmd", choices=["status", "push", "clear", "show"])
    p.add_argument("--onos", default="http://127.0.0.1:8181/onos/v1")
    p.add_argument("--user", default="onos")
    p.add_argument("--password", default="rocks")
    p.add_argument("--slices", type=int, default=1,
                    help="number of independent concurrent slices to target (default 1)")
    a = p.parse_args()
    o = Onos(a.onos, a.user, a.password)
    if a.cmd == "status":
        print("ONOS version:", o.version())
        for app in ("org.onosproject.openflow", "org.onosproject.fwd", "org.onosproject.proxyarp"):
            print(f"{app}: {o.app_state(app)}")
        for i in range(a.slices):
            print(f"{device_id(i)} available:", o.device_available(device_id(i)))
    elif a.cmd == "push":
        o.clear_rest_flows()
        time.sleep(2)
        rules = multi_slice_policy(a.slices) if a.slices > 1 else lab_policy()
        o.push(rules)
        print("ADDED" if o.wait_added(len(rules), 60) else "NOT all ADDED", f"({len(rules)} rules, {a.slices} slice(s))")
    elif a.cmd == "clear":
        o.clear_rest_flows()
        print("REST flows cleared")
    else:
        for f in o.rest_flows():
            crits = ",".join(c["type"] for c in f["selector"]["criteria"]) or "*"
            print(f'{f["deviceId"]:<24} {f["priority"]:>6} {f["state"]:<8} pkts={f.get("packets", 0):<8} {crits}')
