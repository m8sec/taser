import socket
import dns.zone
import dns.query
import dns.resolver
import dns.reversename
from taser import LOG
from taser.utils import ipv4check


class DNSutils:
    @staticmethod
    def _build_resolver(ns=None, timeout=3):
        ns = ns or []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        if ns:
            resolver.nameservers = [ns] if isinstance(ns, str) else ns
        return resolver

    @staticmethod
    def resolve(host, qtype="A", ns=None, tcp=False, timeout=3, raise_errors=False):
        # Returns str of first result during DNS lookup, primarily used for A/AAAA queries
        result = ''
        try:
            dns_query = DNSutils._build_resolver(ns=ns, timeout=timeout).resolve(host, qtype, tcp=tcp)
            result = dns_query[0].to_text()
        except Exception as e:
            LOG.debug(f'Taser ERR: Failed to resolve:: {host} - {e}')
            if raise_errors:
                raise
        return result

    @staticmethod
    def query(host, qtype="A", ns=None, tcp=False, timeout=3, raise_errors=False):
        # Similar to DNSutils.resolve() but returns array of ALL results from DNS lookup
        result = []
        try:
            for x in DNSutils._build_resolver(ns=ns, timeout=timeout).resolve(host, qtype, tcp=tcp):
                result.append(x.to_text())
        except Exception as e:
            LOG.debug(f'Taser ERR: Failed to resolve:: {host} - {e}')
            if raise_errors:
                raise
        return result

    @staticmethod
    def reverse(host, ns=None, timeout=3, raise_errors=False):
        addr = dns.reversename.from_address(host)
        return DNSutils.query(addr, "PTR", ns=ns, timeout=timeout, raise_errors=raise_errors)

    @staticmethod
    def nameservers(domain, ns=None, timeout=3, raise_errors=False):
        results = []
        for srv in DNSutils.query(domain, 'NS', ns=ns, timeout=timeout, raise_errors=raise_errors):
            results.append(srv[:-1] if srv.endswith('.') else srv)
        return results

    @staticmethod
    def zone_transfer(ns, domain, raise_errors=False):
        results = []
        try:
            ns = ns if ipv4check(ns) else DNSutils.get_ip(ns, raise_errors=raise_errors)
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain))
            names = z.nodes.keys()
            for n in names:
                results.append(z[n].to_text(n))
        except Exception as e:
            LOG.debug(f'Taser ERR: Failed zone transfer:: {domain}@{ns} - {e}')
            if raise_errors:
                raise
        return results

    @staticmethod
    def get_ip(host, raise_errors=False):
        try:
            return socket.gethostbyname(host)
        except Exception as e:
            LOG.debug(f'Taser ERR: Failed to get local IP:: {host} - {e}')
            if raise_errors:
                raise
            return host
