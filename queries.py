from rdflib import Graph

g = Graph()
g.parse("network_traffic.ttl", format="turtle")

# Q1 - Servidores que mais responderam na porta 443
Q1 = """
PREFIX ex: <http://example.org/netsec#>
SELECT ?host (COUNT(?conn) as ?count)
WHERE {
  ?conn a ex:Connection ;
        ex:hasSrcPort 443 ;
        ex:hasSource ?host ;
        ex:hasFlags 18 .
}
GROUP BY ?host
ORDER BY DESC(?count)
LIMIT 10
"""

# Q2 - Detecção de força bruta 
Q2 = """
PREFIX ex: <http://example.org/netsec#>
SELECT ?source ?port (COUNT(?conn) as ?syn_count)
WHERE {
  ?conn a ex:Connection ;
        ex:hasSource ?source ;
        ex:hasDestPort ?port ;
        ex:isSyn 1 .
}
GROUP BY ?source ?port
HAVING (COUNT(?conn) > 50)
ORDER BY DESC(?syn_count)
"""

# Q3 - Detecção de escaneamento de portas
Q3 = """
PREFIX ex: <http://example.org/netsec#>
SELECT ?source (COUNT(DISTINCT ?port) as ?unique_ports)
WHERE {
  ?conn a ex:Connection ;
        ex:hasSource ?source ;
        ex:hasDestPort ?port .
}
GROUP BY ?source
HAVING (COUNT(DISTINCT ?port) > 10)
ORDER BY DESC(?unique_ports)
"""

print("--- Resultados Q1 (Top Servidores na Porta 443) ---")
for row in g.query(Q1):
    print(f"Host: {row.host}, Conexões: {row['count']}")

print("\n--- Resultados Q2 (Detecção de Força Bruta - >50 SYNs) ---")
for row in g.query(Q2):
    print(f"Origem: {row.source}, Porta: {row.port}, SYNs: {row.syn_count}")

print("\n--- Resultados Q3 (Detecção de Escaneamento - >10 Portas) ---")
for row in g.query(Q3):
    print(f"Origem: {row.source}, Portas Distintas: {row.unique_ports}")
