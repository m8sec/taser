import socket
import dns.name
import dns.zone
import dns.query
import dns.resolver
import dns.reversename

def dns_lookup(host, dns_lookup, nameserver=[]):
    # Lookups = ['A','NS','MX','TXT','CNAME','HINFO','PTR','SOA','SPF','SRV','RP']
    results = []
    res = dns.resolver.Resolver()
    res.timeout = 3
    res.lifetime = 3
    if nameserver:
        res.nameservers = nameserver
    dns_query = res.query(host, dns_lookup)
    for name in dns_query:
        results.append(str(name))
    return results

def reverse_lookup(host, nameserver=[]):
    addr = dns.reversename.from_address(host)
    return dns_lookup(addr, "PTR", nameserver=nameserver)

def get_nameServers(domain, nameserver=[]):
    results = []
    for srv in dns_lookup(domain, 'NS', nameserver=nameserver):
        results.append(get_ip(srv))
    return results

def zone_transfer(ns, domain):
    results = []
    z = dns.zone.from_xfr(dns.query.xfr(ns, domain))
    names = z.nodes.keys()
    for n in names:
        results.append(z[n].to_text(n))
    return results

def get_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return host