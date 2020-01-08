from __future__ import print_function
import dns_compare

domains = [
    'globaldots.com',
    'danidin.net',
]

domains = [
    'globaldots.com',
    'danidin.net'
]

arguments = dict(
    DEBUG=False,
    zone=None,
    original_dns="dyn",
    current_nameserver="dns1.p03.nsone.net",
    verbose=False,
    compare_soa=False,
    compare_ns=False,
    compare_ttl=False,
    lookup_cnames =  True,
    output="table",
    header = False,

)

# output header, as header is suppressed on the main funtion
print("{}\t{}\t{}\t{}\t{}".format("zone", "record", "status", "expected_value", "received_value"))

for domain in domains:
    arguments["zone"]=domain
    dns_compare.DNSCompare(**arguments)
