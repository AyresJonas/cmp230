from rdflib import Graph, Namespace, Literal, RDF
from bcc import BPF

import threading
import ipaddress
import argparse
import psutil
import time
import os

parser = argparse.ArgumentParser()
parser.add_argument("--interface", default="enp0s3")
parser.add_argument("--duration", type=int, default=180)
parser.add_argument("--output", default="network_traffic.ttl")
parser.add_argument("--page_cnt", type=int, default=512)
parser.add_argument("--xdp_mode", type=int, default=2)
args = parser.parse_args()

if os.geteuid() != 0:
    sys.exit("sudo needed")

EX = Namespace("http://example.org/netsec#")
graph = Graph()
graph.bind("ex", EX)

latencies = []
cpu_usages = []
mem_usages = []
lost_events = 0
pkt_count = 0

proc = psutil.Process(os.getpid())
proc.cpu_percent(None)
start_capture = time.time()

lock = threading.Lock()

bpf = BPF(src_file="xdp_extract.c")
fn = bpf.load_func("xdp_prog", BPF.XDP)


def process_packet(cpu, data, size):
    global pkt_count

    start_time = time.perf_counter()
    
    try:
        event = bpf["pkt_events"].event(data)
        
        src_ip = event.src_ip
        dst_ip = event.dst_ip
        src_port = event.src_port
        dst_port = event.dst_port
        flags = int(event.tcp_flags)
        is_syn = 1 if (flags & 0x12) == 0x02 else 0
        timestamp = int(event.ts_ns)
        
    except Exception as exc:
        print(exc)
        return

    with lock:
        pkt_count += 1
        current_pkt = pkt_count

    conn_uri = EX[f"conn_{current_pkt}_{timestamp}"]
    src_host_uri = EX[f"host_{str(ipaddress.IPv4Address(src_ip))}"]
    dst_host_uri = EX[f"host_{str(ipaddress.IPv4Address(dst_ip))}:{dst_port}"]

    graph.add((conn_uri, RDF.type, EX.Connection))
    graph.add((conn_uri, EX.hasSource, src_host_uri))
    graph.add((conn_uri, EX.hasDest, dst_host_uri))
    graph.add((conn_uri, EX.hasSrcPort, Literal(src_port)))
    graph.add((conn_uri, EX.hasDestPort, Literal(dst_port)))
    graph.add((conn_uri, EX.hasFlags, Literal(flags)))
    graph.add((conn_uri, EX.hasTimestamp, Literal(timestamp)))
    graph.add((conn_uri, EX.isSyn, Literal(is_syn)))
    graph.add((src_host_uri, EX.connectsTo, dst_host_uri))
    
    end_time = time.perf_counter()
    latency_ms = (end_time - start_time) * 1000

    with lock:
        latencies.append((time.time() - start_capture, latency_ms))
        if len(latencies) % 100 == 0:
            cpu_usages.append(proc.cpu_percent(None))
            mem_usages.append(proc.memory_info().rss / (1024 * 1024))


def lost_cb(cpu, n):
    global lost_events
    lost_events += n


try:
    bpf.attach_xdp(args.interface, fn, args.xdp_mode)

    bpf["pkt_events"].open_perf_buffer(process_packet, lost_cb=lost_cb, page_cnt=args.page_cnt)
    print(f"Capturando tráfego na interface {args.interface} por {args.duration} segundos...")

    while time.time() - start_capture < args.duration:
        bpf.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    pass
finally:
    bpf.remove_xdp(args.interface, args.xdp_mode)
    
    print("Serializando grafo RDF...")
    graph.serialize(destination=args.output, format="turtle")
    
    if latencies:
        avg_latency = sum(l for _, l in latencies) / len(latencies)
        print(f"Latência média por evento: {avg_latency:.2f} ms")
    if cpu_usages:
        print(f"Uso médio de CPU (Python): {sum(cpu_usages)/len(cpu_usages):.2f}%")
    if mem_usages:
        print(f"Uso médio de RAM: {sum(mem_usages)/len(mem_usages):.2f} MB")
    
    print(f"Captura finalizada. Grafo salvo em {args.output}")
    print(f"Eventos perdidos no perf buffer: {lost_events}")
