import socket
import dns.resolver
import dns.reversename

#DNS_TYPES = ['A','NS','MX','TXT','CNAME','HINFO','PTR','SOA','SPF','SRV','RP']

def dns_lookup(host, dns_lookup, dns_srv=['1.1.1.1','8.8.8.8']):
    '''
    For lookup using local srv, dns_srv=[]
    '''
    results = []
    try:
        res = dns.resolver.Resolver()
        res.timeout = 3
        res.lifetime = 3
        dns_query = res.query(host, dns_lookup)
        dns_query.nameservers = dns_srv
        for name in dns_query:
            results.append(str(name))
    except:
        pass
    return results

def reverse_lookup(host, dns_srv=['1.1.1.1','8.8.8.8']):
    try:
        addr = dns.reversename.from_address(host)
        return dns_lookup(addr, "PTR", dns_srv=dns_srv)
    except:
        return []

def get_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return host