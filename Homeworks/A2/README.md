# CS425 - Assignment 2
### Group Details 
- Adarsh Sharma (210046)
- Gary Derrick Anderson J (210383)
- Pranjal Singh (218070744)

## Usage Instructions
- The user needs to specify iterative or recursive DNS, and the domain name.
- Please avoid protocol prefixes like `https://` or `sftp://`.
- Trailing slashes are not part of the domain name, but will be removed 
  automatically (`iitk.ac.in/`)
- Sample usage:
```sh
$ python3 dnsresolver.py iterative music.youtube.com
$ python3 dnsresolver.py recursive hello.iitk.ac.in
```
- An error message is printed in case of invalid input. The user can 
  refer to it to correct the arguments.

## High-level Code Flow
- The entry is at the if block at the end (provided in template)
- There are separate functions for recursive and iterative DNS.
- We use IPv4 throughout, and reject IPv6 RRs (type AAAA).

### Recursive DNS
- Recursive DNS is straightforward to implement. We set the Recursion Desired 
  (RD) flag in the DNS header.
- We modified `send_dns_query` to accept an optional recursion flag, which is 
  disabled by default.
- We use Google's DNS server for recursive DNS (8.8.8.8).

### Iterative DNS
- As per the provided template, at each stage, there is a list of servers 
  to try. (`next_ns_list`)
- At each stage, the list is updated by `extract_next_nameservers()`
- First, we check if the ANSWER segment of the response has the final IP 
  address or a canonical name (type CNAME).
- If the final address is available, it is printed and the program exits.
- If a canonical name is returned, the function restarts querying from the 
  root servers. This can be verified by checking the "stage" of resolution 
  being displayed on the console. Some examples are provided in the Test Cases
  section.

## Handling Failures
### Timeout
- Timeouts are handled by the DNS library. The user needs to provide a `timeout = *` 
  flag in `dns.query.udp()`.
- In case of a timeout, we try using the next server from the list of servers.
### Non-existent Domains
- The response message has status equal to 3 for non-existent domains.
- An error is displayed on the console.

## Test Cases
- `music.youtube.com`
- `documentcloud.adobe.com` - Uses a separate canonical name (CNAME)
- `portal.iitb.ac.in`
- `moodle.cse.iith.ac.in`
- `hello.iitk.ac.in` - works only with recursive DNS, as IITK's authoritative server 
   refuses messages from the intranet.
- `admissions.mit.edu` - also uses a canonical name 

## Results
- Most queries are answered in 0.5 to 3 seconds.
- In some cases, a server does not respond within the 3-second timeout.
- In these cases, the program uses the next available DNS server.
- In our testing, all valid domains were resolved. Some fraction needed
  multiple attempts by the program, which is done automatically.
