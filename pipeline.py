from rdflib import Graph, Namespace, Literal, RDF
from scapy.all import IP, TCP
from bcc import BPF
import threading
import psutil
import socket
import time
import os

EX = Namespace("http://example.org/netsec#")
graph = Graph()
graph.bind("ex", EX)

graph_dst_file = "network_traffic.ttl"

latencies = []
cpu_usages = []
mem_usages = []

lost_events = 0
proc = psutil.Process(os.getpid())
proc.cpu_percent(None)
start_capture = time.time()

lock = threading.Lock()

bpf = BPF(src_file="xdp_extract.c")
interface = "enp0s3"
fn = bpf.load_func("xdp_prog", BPF.XDP)
bpf.attach_xdp(interface, fn, BPF.XDP_FLAGS_SKB_MODE)

def process_packet(cpu, data, size):
    start_time = time.perf_counter()
    
    try:
        event = bpf["pkt_events"].event(data)
        
        src_ip_str = socket.inet_ntoa(event.src_ip.to_bytes(4, 'big'))
        dst_ip_str = socket.inet_ntoa(event.dst_ip.to_bytes(4, 'big'))
        
        pkt = IP(src=src_ip_str, dst=dst_ip_str) / TCP(
            sport=event.src_port, 
            dport=event.dst_port, 
            flags=event.tcp_flags
        )
        
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        flags = int(tcp_layer.flags)
        is_syn = 1 if (flags & 0x12) == 0x02 else 0
        
    except Exception:
        return

    timestamp = int(time.time() * 1000)
    conn_id = f"conn_{timestamp}_{src_ip}_{src_port}"
    
    conn_uri = EX[conn_id]
    src_host_uri = EX[f"host_{src_ip}"]
    dst_host_uri = EX[f"host_{dst_ip}:{dst_port}"]
    
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

bpf["pkt_events"].open_perf_buffer(process_packet, lost_cb=lost_cb)

print(f"Capturando tráfego na interface {interface} por 180 segundos...")

try:
    while time.time() - start_capture < 180:
        bpf.perf_buffer_poll(timeout=100)
except KeyboardInterrupt:
    pass
finally:
    bpf.remove_xdp(interface, BPF.XDP_FLAGS_SKB_MODE)
    
    print("Serializando grafo RDF...")
    graph.serialize(destination=graph_dst_file, format="turtle")
    
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        print(f"Latência média por evento: {avg_latency:.2f} ms")
    if cpu_usages:
        print(f"Uso médio de CPU (Python): {sum(cpu_usages)/len(cpu_usages):.2f}%")
    if mem_usages:
        print(f"Memória residente média: {sum(mem_usages)/len(mem_usages):.2f} MB")
    
    print(f"Captura finalizada. Grafo salvo em {graph_dst_file}")