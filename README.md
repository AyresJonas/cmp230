Captura pacotes TCP com eBPF/XDP, extrai campos (IPs, portas, flags), gera triplas RDF em um grafo de conhecimento local (RDFlib) e executa consultas SPARQL (atualmente):
- Top hosts que acessam a porta 443
- Possíveis ataques de força bruta (muitos SYNs para a mesma porta)
- Possível escaneamento de portas (muitas portas distintas acessadas)

## dependências
python
pip

## rodando

- ajustar interface de rede no arquivo pipeline.py (var interface)
- gerar tráfego TCP (browser, curl, simulações)

```
sudo apt update
sudo apt install python3-bpfcc bpfcc-tools libbpfcc
pip install --user --break-system-packages -r requirements.txt
python pipeline.py
```

## exemplo de saída esperada
- [Q1] Hosts que mais se comunicam na porta 443: http://example.org/netsec#host_192.168.1.10  ->  50 conexões
- [Q2] Possíveis ataques de força bruta (SYN > 5 por host/porta): http://example.org/netsec#host_10.0.0.99  -> porta 22: 200 SYNs
- [Q3] Possível escaneamento de portas: http://example.org/netsec#host_10.0.0.99  -> 10 portas distintas
