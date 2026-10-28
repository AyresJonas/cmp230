# Network Traffic Modeling as Knowledge Graphs (eBPF/XDP + RDF/SPARQL)

A lightweight, modular pipeline that captures live IPv4/TCP network traffic directly in the Linux kernel using **eBPF/XDP**, models extracted packet headers as a dynamic **RDF Knowledge Graph** via **RDFlib**, and executes **SPARQL** queries for semantic network security analysis.

Currently, `queries.py` implements three security-oriented queries:
- **Q1 – Port 443 Hits:** Lists the top 10 hosts responding from source port `443`.
- **Q2 – Brute-Force Detection:** Flags `(source, destination_port)` pairs exceeding `50` TCP `SYN` packets.
- **Q3 – Port Scanning Detection:** Identifies source hosts sending TCP `SYN` packets to more than `10` distinct destination ports.

---

## Repository Structure

- `xdp_extract.c` — Kernel-space eBPF/XDP program that parses Ethernet, IPv4, and TCP headers in ingress mode and exports packet metadata (`ts_ns`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `tcp_flags`) to userspace via a `perf_buffer`.
- `pipeline.py` — Userspace collector that reads packet events from the `perf_buffer`, maps them into RDF triples under the `http://example.org/netsec#` namespace using `RDFlib` (with IP/URI caching and batched `addN` insertions), tracks latency/CPU/RAM overhead, and serializes the graph in N-Triples format (`.ttl`).
- `queries.py` — Parses the serialized `.ttl` graph and runs SPARQL queries (Q1–Q3).
- `requirements.txt` — Python dependencies (`rdflib`, `psutil`).

---

## Dependencies

### System Packages (Ubuntu / Debian)
```bash
sudo apt update
sudo apt install -y python3-bpfcc bpfcc-tools libbpfcc linux-headers-$(uname -r) tcpdump tcpreplay
```

### Python Packages
```bash
pip install --user --break-system-packages -r requirements.txt
```

---

## Usage

### 1. Start the eBPF/XDP Capture Pipeline (Monitor VM)
Root privileges (`sudo`) are required to attach the XDP program to a network interface:

```bash
sudo python3 pipeline.py
```

**Available CLI options for `pipeline.py`:**
- `--interface` — Network interface to monitor (default: `enp0s3`).
- `--timeout` — Capture duration in seconds (default: `360`). Press `Ctrl+C` at any time to stop early and serialize the graph.
- `--output` — Output file path (default: `network_traffic.ttl`).
- `--page_cnt` — Number of pages allocated per CPU for the `perf_buffer` (default: `1024`).
- `--xdp_mode` — XDP attach mode flags: `2` for SKB/generic mode (recommended for virtual interfaces), `4` for native/driver mode (default: `2`).

### 2. Generate or Replay Traffic
Generate live TCP traffic (`curl`, web browsing, `nmap`, `hping3`) or replay real backbone traces from the [MAWI Working Group Traffic Archive](https://mawi.wide.ad.jp/mawi/).

Since MAWI `samplepoint-F` traces are distributed as raw IP captures (`DLT_RAW`), prepend an Ethernet header addressed to the Monitor VM's MAC before replaying:

```bash
tcprewrite --dlt=enet \
  --enet-smac=<GENERATOR_MAC> \
  --enet-dmac=<MONITOR_MAC> \
  -i mawi_sample_raw.pcap \
  -o mawi_sample_eth.pcap

sudo tcpreplay -i <port> --mbps=10 <file_eth>.pcap
```

Once the capture timeout expires (or after pressing `Ctrl+C`), `pipeline.py` detaches the XDP hook, serializes the `.ttl` file, and prints performance metrics (`avg event latency`, `avg cpu usage`, `avg ram usage`, and `perf buffer lost events`).

### 3. Run SPARQL Queries
Execute the analytical queries against the generated file:

```bash
python3 queries.py
```

**Available CLI options for `queries.py`:**
- `--input` — Path to the serialized `.ttl` graph file (default: `network_traffic.ttl`).

---

## Expected Output Example

### `pipeline.py`
```text
listening on interface enp0s3 for 360 secs...
serializing RDF graph...
triples: 656353 | tcp pkts: 72928 | size: 22.75 MB
avg event latency: 0.33 ms
avg cpu usage: 54.60%
avg ram usage: 340.99 MB
finished. Output: network_traffic.ttl
perf buffer lost events: 0
```

### `queries.py`
```text
--- q1: 443 port hits ---
Host: http://example.org/netsec#host_172.217.62.53 -> 8437
Host: http://example.org/netsec#host_130.9.200.142 -> 3859

--- q2: brute force detection (>50 SYNs) ---
source: http://example.org/netsec#host_207.253.119.233, port: 30000, SYNs: 128
source: http://example.org/netsec#host_207.253.119.231, port: 17771, SYNs: 123

--- q3: multiple port hits (>10 ports) ---
source: http://example.org/netsec#host_172.234.77.88, distinct ports: 32
source: http://example.org/netsec#host_79.135.250.142, distinct ports: 26
```
