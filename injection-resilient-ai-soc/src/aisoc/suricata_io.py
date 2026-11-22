"""Run Suricata on a pcap and turn eve.json into one record per flow.

Each record separates:
  * trusted, sensor-generated fields (5-tuple, counters, timings, Suricata alerts)
  * untrusted, attacker-controllable fields (URI, User-Agent, Referer, headers, DNS query)
That separation is what Judge A (numbers only) and the provenance prompt rely on.
"""
import json
import os
import shutil
import subprocess
from collections import defaultdict

import pandas as pd

UNTRUSTED_HTTP_HEADERS = {"user-agent", "referer", "x-forwarded-for", "cookie", "host"}


def run_suricata(pcap, rules, outdir, suricata_bin=None, config=None, home_net="[10.10.0.0/16,192.168.0.0/16]"):
    suricata_bin = suricata_bin or shutil.which("suricata") or "suricata"
    if os.path.isdir(outdir):
        shutil.rmtree(outdir)
    os.makedirs(outdir)
    cmd = [suricata_bin, "-r", pcap, "-S", rules, "-l", outdir, "-k", "none", "--runmode", "single",
           "--set", f"vars.address-groups.HOME_NET={home_net}",
           "--set", "outputs.1.eve-log.types.3.http.extended=yes"]
    if config:
        cmd[1:1] = ["-c", config]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Suricata failed:\n{res.stderr[-2000:]}")
    return os.path.join(outdir, "eve.json")


def _key(ev):
    return (ev.get("src_ip"), int(ev.get("src_port", 0) or 0), ev.get("dest_ip"),
            int(ev.get("dest_port", 0) or 0), ev.get("proto"))


def parse_eve(eve_path):
    flows, alerts, http, dns = {}, defaultdict(list), defaultdict(list), defaultdict(list)
    with open(eve_path) as f:
        for line in f:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            et = ev.get("event_type")
            if et == "flow":
                flows[_key(ev)] = ev
            elif et == "alert":
                alerts[_key(ev)].append(ev)
            elif et == "http":
                http[_key(ev)].append(ev.get("http", {}))
            elif et == "dns":
                d = ev.get("dns", {})
                # Suricata 7: dns.queries[] or dns.rrname; keep the query name
                q = d.get("rrname") or (d.get("queries") or [{}])[0].get("rrname")
                if q and (d.get("type") in (None, "query", "request")):
                    dns[_key(ev)].append(q)

    rows = []
    for k, fl in flows.items():
        f = fl.get("flow", {})
        tcp = fl.get("tcp", {})
        h = http.get(k, [{}])[0] if http.get(k) else {}
        hdrs = {x.get("name", "").lower(): x.get("value", "") for x in h.get("request_headers", [])}
        al = alerts.get(k, [])
        rows.append({
            "src_ip": k[0], "src_port": k[1], "dest_ip": k[2], "dest_port": k[3], "proto": k[4],
            "app_proto": fl.get("app_proto", "none"),
            # ---- trusted numeric telemetry ----
            "pkts_toserver": f.get("pkts_toserver", 0), "pkts_toclient": f.get("pkts_toclient", 0),
            "bytes_toserver": f.get("bytes_toserver", 0), "bytes_toclient": f.get("bytes_toclient", 0),
            "age": f.get("age", 0), "state": f.get("state", ""),
            "start": pd.Timestamp(f.get("start")).timestamp() if f.get("start") else 0.0,
            "tcp_syn": int(bool(tcp.get("syn"))), "tcp_fin": int(bool(tcp.get("fin"))),
            "tcp_rst": int(bool(tcp.get("rst"))), "tcp_psh": int(bool(tcp.get("psh"))),
            "http_status": int(h.get("status", 0) or 0), "http_method": h.get("http_method", ""),
            "http_resp_len": int(h.get("length", 0) or 0),
            # ---- trusted Suricata verdicts ----
            "alert_sigs": [a["alert"]["signature"] for a in al],
            "alert_sids": [a["alert"]["signature_id"] for a in al],
            "alert_sevs": [a["alert"]["severity"] for a in al],
            "alert_max_sev": min([a["alert"]["severity"] for a in al], default=0),
            # ---- UNTRUSTED attacker-controllable text ----
            "untrusted": {
                "http.uri": h.get("url", ""),
                "http.user_agent": h.get("http_user_agent", ""),
                "http.referer": hdrs.get("referer", h.get("http_refer", "")),
                "http.x_forwarded_for": hdrs.get("x-forwarded-for", ""),
                "dns.query": (dns.get(k) or [""])[0],
            },
        })
    return pd.DataFrame(rows)


def join_labels(df, labels_csv):
    lab = pd.read_csv(labels_csv)
    lab["proto"] = lab["proto"].astype(str)
    m = df.merge(lab, on=["src_ip", "src_port", "dest_ip", "dest_port", "proto"], how="inner")
    return m
