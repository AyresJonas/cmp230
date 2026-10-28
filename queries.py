from rdflib import Graph
import argparse
import sys
import os


parser = argparse.ArgumentParser()
parser.add_argument("--input", default="network_traffic.ttl")
args = parser.parse_args()

if not os.path.isfile(args.input):
    sys.exit(f"'{args.input}' not found")

g = Graph()
g.parse(args.input, format="turtle")

# Q1 - 443 port hits
Q1 = """
PREFIX ex: <http://example.org/netsec#>
SELECT ?host (COUNT(?conn) as ?count)
WHERE {
  ?conn ex:hasSrcPort 443 ;
        a ex:Connection ;
        ex:hasSource ?host .
}
GROUP BY ?host
ORDER BY DESC(?count)
LIMIT 10
"""

# Q2 - brute force detection
Q2 = """
PREFIX ex: <http://example.org/netsec#>
SELECT ?source ?port (COUNT(?conn) as ?syn_count)
WHERE {
  ?conn ex:isSyn 1 ;
        a ex:Connection ;
        ex:hasSource ?source ;
        ex:hasDestPort ?port .
}
GROUP BY ?source ?port
HAVING (COUNT(?conn) > 50)
ORDER BY DESC(?syn_count)
"""

# Q3 - multiple port hits
Q3 = """
PREFIX ex: <http://example.org/netsec#>
SELECT ?source (COUNT(DISTINCT ?port) as ?unique_ports)
WHERE {
  ?conn ex:isSyn 1 ;
        a ex:Connection ;
        ex:hasSource ?source ;
        ex:hasDestPort ?port .
}
GROUP BY ?source
HAVING (COUNT(DISTINCT ?port) > 10)
ORDER BY DESC(?unique_ports)
"""

print("--- q1: 443 port hits ---")
for row in g.query(Q1):
    print(f"Host: {row.host} -> {row['count']}")

print("\n--- q2: brute force detection (>50 SYNs) ---")
for row in g.query(Q2):
    print(f"source: {row.source}, port: {row.port}, SYNs: {row.syn_count}")

print("\n--- q3: multiple port hits (>10 ports) ---")
for row in g.query(Q3):
    print(f"source: {row.source}, distinct ports: {row.unique_ports}")
