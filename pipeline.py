from rdflib import Graph, Namespace, Literal, URIRef, RDF
from bcc import BPF
import argparse
import signal
import socket
import struct
import psutil
import time
import sys
import os


parser = argparse.ArgumentParser()
parser.add_argument("--interface", default="enp0s3")
parser.add_argument("--timeout", type=int, default=360)
parser.add_argument("--output", default="network_traffic.ttl")
parser.add_argument("--page_cnt", type=int, default=1024)
parser.add_argument("--xdp_mode", type=int, default=2)
args = parser.parse_args()

if os.geteuid() != 0:
    sys.exit("sudo needed")

running = True

def handle_sigint(signum, frame):
    global running
    running = False


signal.signal(signal.SIGINT, handle_sigint)

EX_BASE = "http://example.org/netsec#"
EX = Namespace(EX_BASE)
graph = Graph()
graph.bind("ex", EX)

RDF_TYPE = RDF.type
EX_CONNECTION = EX.Connection
EX_HAS_SOURCE = EX.hasSource
EX_HAS_DEST = EX.hasDest
EX_HAS_SRC_PORT = EX.hasSrcPort
EX_HAS_DEST_PORT = EX.hasDestPort
EX_HAS_FLAGS = EX.hasFlags
EX_HAS_TIMESTAMP = EX.hasTimestamp
EX_IS_SYN = EX.isSyn
EX_CONNECTS_TO = EX.connectsTo
LIT_ZERO = Literal(0)
LIT_ONE = Literal(1)

ip_cache = {}
src_uri_cache = {}

latencies = []
cpu_usages = []
mem_usages = []
lost_events = 0
pkt_count = 0

proc = psutil.Process(os.getpid())
proc.cpu_percent(None)
start_capture = time.time()

bpf = BPF(src_file="xdp_extract.c")
fn = bpf.load_func("xdp_prog", BPF.XDP)
pkt_events = bpf["pkt_events"]


def int_to_ip(ip_int):
    ip_str = ip_cache.get(ip_int)
    if ip_str is None:
        ip_str = socket.inet_ntoa(struct.pack("!I", ip_int))
        ip_cache[ip_int] = ip_str
    return ip_str


def get_src_uri(ip_int):
    uri = src_uri_cache.get(ip_int)
    if uri is None:
        uri = URIRef(f"{EX_BASE}host_{int_to_ip(ip_int)}")
        src_uri_cache[ip_int] = uri
    return uri


def process_packet(cpu, data, size):
    global pkt_count

    if not running:
        return

    start_time = time.perf_counter()

    try:
        event = pkt_events.event(data)

        src_ip = event.src_ip
        dst_ip = event.dst_ip
        src_port = int(event.src_port)
        dst_port = int(event.dst_port)
        flags = int(event.tcp_flags)
        is_syn_lit = LIT_ONE if (flags & 0x12) == 0x02 else LIT_ZERO
        timestamp = int(event.ts_ns)

    except Exception as exc:
        print(exc)
        return

    pkt_count += 1

    conn_uri = URIRef(f"{EX_BASE}conn_{pkt_count}_{timestamp}")
    src_host_uri = get_src_uri(src_ip)
    dst_host_uri = URIRef(f"{EX_BASE}host_{int_to_ip(dst_ip)}:{dst_port}")

    graph.addN((
        (conn_uri, RDF_TYPE, EX_CONNECTION, graph),
        (conn_uri, EX_HAS_SOURCE, src_host_uri, graph),
        (conn_uri, EX_HAS_DEST, dst_host_uri, graph),
        (conn_uri, EX_HAS_SRC_PORT, Literal(src_port), graph),
        (conn_uri, EX_HAS_DEST_PORT, Literal(dst_port), graph),
        (conn_uri, EX_HAS_FLAGS, Literal(flags), graph),
        (conn_uri, EX_HAS_TIMESTAMP, Literal(timestamp), graph),
        (conn_uri, EX_IS_SYN, is_syn_lit, graph),
        (src_host_uri, EX_CONNECTS_TO, dst_host_uri, graph),
    ))

    latency_ms = (time.perf_counter() - start_time) * 1000
    latencies.append((time.time() - start_capture, latency_ms))

    if pkt_count % 1000 == 0:
        cpu_usages.append(proc.cpu_percent(None))
        mem_usages.append(proc.memory_info().rss / (1024 * 1024))


def lost_cb(cpu, n):
    global lost_events
    lost_events += n


try:
    bpf.attach_xdp(args.interface, fn, args.xdp_mode)

    pkt_events.open_perf_buffer(process_packet, lost_cb=lost_cb, page_cnt=args.page_cnt)
    print(f"listening on interface {args.interface} for {args.timeout} secs...")

    while running and (time.time() - start_capture < args.timeout):
        bpf.perf_buffer_poll(timeout=100)
finally:
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    bpf.remove_xdp(args.interface, args.xdp_mode)
    del pkt_events
    bpf.cleanup()

    print("serializing RDF graph...")
    graph.serialize(destination=args.output, format="nt", encoding="utf-8")

    file_size = os.path.getsize(args.output) / (1024 * 1024)
    print(f"triples: {len(graph)} | tcp pkts: {pkt_count} | size: {file_size:.2f} MB")

    if latencies:
        avg_latency = sum(l for _, l in latencies) / len(latencies)
        print(f"avg event latency: {avg_latency:.2f} ms")
    if cpu_usages:
        print(f"avg cpu usage: {sum(cpu_usages)/len(cpu_usages):.2f}%")
    if mem_usages:
        print(f"avg ram usage: {sum(mem_usages)/len(mem_usages):.2f} MB")

    print(f"finished. Output: {args.output}")
    print(f"perf buffer lost events: {lost_events}")
