import socket
import dns.name
import dns.zone
import dns.query
import dns.resolver
import dns.reversename
from taser.utils import ipcheck


class DNSutils:
    @staticmethod
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

    @staticmethod
    def reverse_lookup(host, nameserver=[]):
        addr = dns.reversename.from_address(host)
        return DNSutils.dns_lookup(addr, "PTR", nameserver=nameserver)

    @staticmethod
    def get_nameservers(domain, nameserver=[]):
        results = []
        for srv in DNSutils.dns_lookup(domain, 'NS', nameserver=nameserver):
            results.append(srv[:-1] if srv.endswith('.') else srv)
        return results

    @staticmethod
    def zone_transfer(ns, domain):
        results = []
        ns = ns if ipcheck(ns) else DNSutils.get_ip(ns)
        z = dns.zone.from_xfr(dns.query.xfr(ns, domain))
        names = z.nodes.keys()
        for n in names:
            results.append(z[n].to_text(n))
        return results

    @staticmethod
    def get_ip(host):
        try:
            return socket.gethostbyname(host)
        except:
            return host