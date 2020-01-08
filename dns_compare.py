from __future__ import print_function

# Original script by joe miller, <joeym@joeym.net>, 12/16/2010
# https://github.com/joemiller/dns_compare/blob/master/dns_compare

# Original uses a bind file as source, but that is a privilege we don't have.
# We must use AXFR results, which are in a different format and have somewhat different values for CNAME and apex values.

# modified to support AXFR results instead of bind file
# modified for python 3
# modified to use argparse instead of optparse
# added output format argument
# Shalom Carmel, 2019-12

import argparse
import sys, socket

TIMEOUT = 15.0

DEBUG=False

zone_transfer_map = {
    "dyn": 'xfrout1.dynect.net',
    "ns1": 'xfr01.nsone.net',
    "ultradns": '54.197.245.255'
}
try:
    import dns.resolver, dns.zone
    from dns.exception import DNSException
    from dns.rdataclass import *
    from dns.rdatatype import *
except ImportError:
    print("Please install dnspython:")
    print( "$ sudo pip install dnspython")
    sys.exit(1)


def DNSCompare(**kwargs):
    global zone_transfer_map
    original_dns = kwargs.get("original_dns")
    zonename = kwargs.get("zone")
    current_nameserver = kwargs.get("current_nameserver")
    assert original_dns, "Must know who the original DNS is. Options are: " + ", ".join([origin for origin in zone_transfer_map])
    assert zonename, "Zone cannot be empty"
    assert current_nameserver, "Must have a nameserver to check with"
    # optional parms
    output = kwargs.get("output", "standard")
    compare_soa = kwargs.get("compare_soa", False)
    compare_ns = kwargs.get("compare_ns", False)
    compare_ttl = kwargs.get("compare_ttl", False)
    lookup_cnames = kwargs.get("lookup_cnames", True)
    verbose = kwargs.get("verbose", False)
    print_header = kwargs.get("header", True)

    original_axfr_server = zone_transfer_map.get(original_dns)
    original_zone = dns.zone.from_xfr(dns.query.xfr(original_axfr_server, zonename, lifetime=TIMEOUT))
    migrated_zone = dns.resolver.Resolver(configure=False)

    try:
        migrated_zone.nameservers = socket.gethostbyname_ex(current_nameserver)[2]
    except socket.error:
        print("Error: could not resolve 'host' %s" % current_nameserver)
        sys.exit(3)

    matches=0
    cnamematches=0
    mismatches=0
    if output == 'table' and print_header:
        print("{}\t{}\t{}\t{}\t{}".format("zone", "record", "status", "expected_value", "received_value"))
    for (name, rdataset) in original_zone.iterate_rdatasets():
        if rdataset.rdtype == SOA and not compare_soa:
            continue
        if rdataset.rdtype == NS and not compare_ns:
            continue

        zone = dns.name.from_text(zonename)
        match = False
        result = None
        try:
            fqdn = dns.name.from_text(str(name), origin=zone)
            ans = migrated_zone.query(fqdn, rdataset.rdtype, rdataset.rdclass)
            result = ans.rrset.to_rdataset()
            if result.rdtype==CNAME:
                result = dns.rdataset.from_text(
                    result.rdclass,
                    result.rdtype,
                    result.ttl,
                    str(result[0].target.relativize(zone)) # there can be only 1 answer anyway, so the first one is safe to use
                )
            if result == rdataset:
                if compare_ttl:
                    if result.ttl == rdataset.ttl:
                        match = True
                else:
                    match = True
        except DNSException as e:
            if output == 'standard':
                print(e)
            pass
        if lookup_cnames and match == False and result == None and rdataset.rdtype == dns.rdatatype.CNAME and rdataset.rdclass == dns.rdataclass.IN:
            try:
                ans_a = None
                ans_a = migrated_zone.query(name, dns.rdatatype.A, dns.rdataclass.IN)
                result_a = ans_a.rrset.to_rdataset()
            except:
                pass
            if ans_a != None:
                ans_cname = migrated_zone.query(rdataset[0].target, dns.rdatatype.A, dns.rdataclass.IN)
                result_cname = ans_cname.rrset.to_rdataset()
                print ("----")
                if result_cname == result_a:
                    print ("(%s) query: %s" % ("CName-Match", name))
                    cnamematches += 1
                else:
                    print ("(%s) query: %s" % ("MIS-Match", name))
                    mismatches += 1
                print ("Expected: ", rdataset, ' (', result_cname, ')')
                print( "Received: ", result_a)
                pass

        if verbose:
            description = 'Match' if match else 'MIS-MATCH'
            if output == 'standard':
                print ("----")
                print ("(%s) query: %s" % (description, name))
                if result != None and len(result) > 1:
                    print ("Expected:")
                    print (rdataset)
                    print ("Received: ")
                    print (result)
                else:
                    print ("Expected: ", rdataset)
                    print ("Received: ", result)
            elif output == 'table':
                print ("{}\t{}\t{}\t{}\t{}".format(zonename, name, description, rdataset, result))

        if match:
            if not verbose and output == 'standard':
                sys.stdout.write('.')
                sys.stdout.flush()
            matches += 1
        else:
            if not verbose:
                if output == 'standard':
                    sys.stdout.write('X')
                    print( "\n(MIS-MATCH) query: %s" % name)
                    if result != None and len(result) > 1:
                        print( "Expected:")
                        print( rdataset)
                        print( "Received: ")
                        print( result)
                    else:
                        print( "Expected: ", rdataset)
                        print( "Received: ", result)
                    sys.stdout.flush()
                elif output == 'table':
                    print( "{}\t{}\t{}\t{}\t{}".format(zonename, name, "MIS-MATCH", rdataset, result))
            mismatches += 1
    if output == 'standard':
        print( "done")

        print( "\nResults:")
        print("Compare SOA:\t", compare_soa)
        print("Compare NS:\t", compare_ns)
        print( "Matches:\t", matches)
        if lookup_cnames and cnamematches > 0:
            print( "CName-matches: ", cnamematches)
        print( "Mis-matches:\t", mismatches)
    pass

if __name__ == '__main__':
    # if executed from commandline and -d is the first parm
    if len(sys.argv) > 1 and str(sys.argv[1]).lower() == "-d":
        DEBUG = True
        sys.argv = [sys.argv[0], "-d"]

    # deal with debugging
    if DEBUG:
        default_zone = 'danidin.net'
        required_zone= False
        default_nameserver = 'dns1.p03.nsone.net'
        required_nameserver= False
        print("DEBUG on, force all defaults")
    else:
        default_zone = None
        required_zone= True
        default_nameserver = None
        required_nameserver= True

    parser = argparse.ArgumentParser(description='Verify DNS migration', prog='dns_compare')

    # required options
    parser.add_argument("-d", "--debug", dest="DEBUG", action="store_true", default=False,
                        help="Debug mode. If used, should be first. default: false"
                        )
    parser.add_argument("-z", "--zone", dest="zone", metavar="<domain>",
                        help="name of the domain we're checking (eg: domain.com)",
                        required=required_zone, default=default_zone
                        )
    parser.add_argument("-1", "--original_dns", dest="original_dns", metavar="<Original DNS service>",
                        help="Possible values: " + "|".join([dns_service for dns_service in zone_transfer_map]),
                        choices= [dns_service for dns_service in zone_transfer_map],
                        default="dyn")
    parser.add_argument("-2", "--nameserver", dest="current_nameserver", metavar="<Current NS>",
                        required=required_nameserver, default=default_nameserver)
    # optional ... options
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False,
                        help="print detailed results of each action")
    parser.add_argument("-a","--soa", dest="compare_soa", action="store_true", default=False,
                        help="compare SOA records (default: false)")
    parser.add_argument("-n","--ns", dest="compare_ns", action="store_true", default=False,
                        help="compare NS records (default: false)")
    parser.add_argument("-t","--ttl", dest="compare_ttl", action="store_true", default=False,
                        help="compare TTL values (default: false)")
    parser.add_argument("-c","--cname", dest="lookup_cnames", action="store_true", default=True,
                        help="lookup cname-values that do not match (default: true)")
    parser.add_argument("-o","--output", dest="output",
                        choices = ['standard', 'table'], default= 'standard',
                      help="Output format (default: standard)")
    parser.add_argument("--header", dest="header", action="store_true", default=True,
                        help="for table output, whether to print headers (default: true)")
    opts = parser.parse_args()

    # check for required options, since optparse doesn't support required options
    if not opts.zone or not opts.original_dns or not opts.current_nameserver  :
        parser.error( "required arguments: --zone, --nameserver  (or --help)")

    arguments = dict(
        DEBUG = opts.DEBUG,
        zone = opts.zone,
        original_dns = opts.original_dns,
        current_nameserver = opts.current_nameserver,
        verbose = opts.verbose,
        compare_soa = opts.compare_soa,
        compare_ns = opts.compare_ns,
        compare_ttl = opts.compare_ttl,
        lookup_cnames = opts.lookup_cnames,
        output = opts.output,
        header=opts.header
    )
    DNSCompare(**arguments)
