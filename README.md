DNS Compare
==========
This tool supports validations of large scale migrations between DNS vendors. 
It compares a zone from the original DNS with the new zone at the new DNS service. 

To do that, the tool does a zone transfer from the original DNS, and then checks all of the original records with the new service to find mis-matches. 

By default, the tool does not compare NS records or SOA records, as these will be different by definition. 

dns_compare cli
============= 
The basic usage, invoked by the `dns_compare` command, is perfect for a small number of domains or manual checks.

The `--output table` option print a tab separated list, that can be redirected into a file and input into a spreadsheet or a database.
 
Use the tool for large scale comparisons
================
An example of large scale work can be found in `dns_compare_list.py`

Usage examples
==========
Show help with all of the options: 

`dns_compare   --help`

Check with Dyn as origin, and output exceptions

`dns_compare   --zone acme.com  --original_dns  dyn   --nameserver pdns110.ultradns.com`

Check with Dyn as origin, and output exceptions as tab separated
 
`dns_compare   --zone acme.com  --original_dns  dyn   --nameserver pdns110.ultradns.com  --output table`

Check with Dyn as origin, and output everything
 
`dns_compare   --zone acme.com  --original_dns  dyn   --nameserver pdns110.ultradns.com  --verbose `


Prerequisites
==========
- On the original DNS, allow zone transfer from your IP address. 
- *Python*
- The *dnspython* module. The tool will notify you if it is missing :) 



Credits
=========
Original script by joe miller, <joeym@joeym.net>, 12/16/2010

https://github.com/joemiller/dns_compare/blob/master/dns_compare

Original uses a bind file as source, but that is a privilege we don't have as we migrate at scale using zone transfers. 
We must use AXFR results, which are in a different format than a bind file.
