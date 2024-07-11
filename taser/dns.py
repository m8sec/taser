import socket
import dns.name
import dns.zone
import dns.query
import dns.resolver
import dns.reversename
from taser import LOG
from taser.utils import ipcheck


class DNSutils:
    @staticmethod
    def resolve(host, qtype="A", ns=[], tcp=False, timeout=3):
        # Returns str of first result during DNS lookup, primarily used for A/AAAA queries
        result = ''
        try:
            res = dns.resolver.Resolver()
            res.lifetime = timeout
            if ns:
                res.nameservers = [ns] if type(ns) == str else ns
            dns.resolver.override_system_resolver(res)
            dns_query = res.resolve(host, qtype, tcp=tcp)
            result = dns_query[0].to_text()
        except Exception as e:
            LOG.debug(f'Taser ERR: Failed to resolve:: {host} - {e}')
        return result

    @staticmethod
    def query(host, qtype="A", ns=[], tcp=False, timeout=3):
        # Similar to DNSutils.resolve() but returns array of ALL results from DNS lookup
        result = []
        try:
            res = dns.resolver.Resolver()
            res.lifetime = timeout
            if ns:
                res.nameservers = [ns] if type(ns) == str else ns
            dns.resolver.override_system_resolver(res)
            for x in res.resolve(host, qtype, tcp=tcp):
                result.append(x.to_text())
        except Exception as e:
            LOG.debug(f'Taser ERR: Failed to resolve:: {host} - {e}')
        return result

    @staticmethod
    def reverse(host, ns=[], timeout=3):
        addr = dns.reversename.from_address(host)
        return DNSutils.query(addr, "PTR", ns=ns, timeout=timeout)

    @staticmethod
    def nameservers(domain, ns=[], timeout=3):
        results = []
        for srv in DNSutils.query(domain, 'NS', ns=ns, timeout=timeout):
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
        except Exception as e:
            LOG.debug(f'Taser ERR: Failed to get local IP:: {host} - {e}')
            return host
