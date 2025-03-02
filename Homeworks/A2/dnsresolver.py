import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import time

debug = 0 # turn on for verbose statements
# Root DNS servers used to start the iterative resolution process
ROOT_SERVERS = {
    "198.41.0.4": "Root (a.root-servers.net)",
    "199.9.14.201": "Root (b.root-servers.net)",
    "192.33.4.12": "Root (c.root-servers.net)",
    "199.7.91.13": "Root (d.root-servers.net)",
    "192.203.230.10": "Root (e.root-servers.net)"
}

TIMEOUT = 3  # Timeout in seconds for each DNS query attempt

def send_dns_query(server, domain, recursive = False):
    """ 
    Sends a DNS query to the given server for an A record of the specified domain.
    Returns the response if successful, otherwise returns None.
    """
    try:
        query = dns.message.make_query(domain, dns.rdatatype.A)  # Construct the DNS query
        if (recursive):
            query.flags |= dns.flags.RD
        else:
            query.flags &= ~(dns.flags.RD)
        # TODO: Send the query using UDP 
        # Note that above TODO can be just a return statement with the UDP query!
        response = dns.query.udp(query, server, timeout=TIMEOUT)
        if response.rcode() == 3:
            print(f"[ERROR] Domain does not exist!")
            return None
    except Exception:
        print(f"[ERROR] Server {server} did not respond")
        return None  # If an error occurs (timeout, unreachable server, etc.), return None
    return response

def extract_next_nameservers(response):
    """ 
    Extracts nameserver (NS) records from the authority section of the response.
    Then, resolves those NS names to IP addresses.
    Returns a list of IPs of the next authoritative nameservers.
    """
    ns_ips = []  # List to store resolved nameserver IPs
    ns_names = []  # List to store nameserver domain names
    
    # Loop through the authority section to extract NS records
    # Authority contains NS names only, we MIGHT find the IP address in additional
    if response.errors:
        if debug:
            print("response errors", response.errors)

    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for rr in rrset:
                ns_name = rr.to_text()
                ns_names.append(ns_name)  # Extract nameserver hostname
                print(f"Extracted NS hostname: {ns_name}")
        elif rrset.rdtype == dns.rdatatype.SOA:
            # print("SOA type") # try poorvi.cse.iitd.ac.in
            rr = rrset[0]
            if debug:
                print(rrset)
                print("SOA:")
                print(type(rr))
                print(dir(rrset))
                print(rrset.name, rrset.items)
            k = (list(rrset.items.keys())[0])
            if debug:
                print(k)
                print(k.to_text())

            ns_name = k
            ns_names.append(ns_name)  # Extract nameserver hostname
            print(f"Extracted NS hostname: {ns_name} FROM SOA TYPE")
        elif rrset.rdtype == dns.rdatatype.CNAME:
            if debug:
                print("CNAME")


    for rrset in response.additional:
        name = rrset.to_text()
        ipversion = name.split()[3]
        assert(ipversion in ["AAAA", "A",  "MX", "CNAME"])
        # get IPv4 addresses
        if ipversion == "AAAA":
            continue
        address = name.split()[-1]
        assert(address[0].isdigit() and address[-1].isdigit() and address.count('.') == 3)

        rr = rrset[0]
        address = rr.to_text()
        name = rrset.name.to_text()
        if (name in ns_names):
            ns_ips.append(address)

    if response.additional == [] or ns_ips == []:
        if debug: print("no additional section in response")
        for ns_name in ns_names:
            try:
                ans = dns.resolver.resolve(ns_name)
                ns_ips.append(ans.response.answer[0][0].to_text())
            except:
                pass

    # TODO: Resolve the extracted NS hostnames to IP addresses
    # To TODO, you would have to write a similar loop as above

    
    return ns_ips  # Return list of resolved nameserver IPs

def iterative_dns_lookup(domain):
    """ 
    Performs an iterative DNS resolution starting from root servers.
    It queries root servers, then TLD servers, then authoritative servers,
    following the hierarchy until an answer is found or resolution fails.
    """
    print(f"[Iterative DNS Lookup] Resolving {domain}")

    next_ns_list = list(ROOT_SERVERS.keys())  # Start with the root server IPs
    stage = "ROOT"  # Track resolution stage (ROOT, TLD, AUTH)
    original_domain = domain # in case we go down a CNAME loop

    while next_ns_list:
        if debug: print("====================================================================")
        ns_ip = next_ns_list[0]  # Pick the first available nameserver to query
        response = send_dns_query(ns_ip, domain)
        
        if response: #checks if response is not NONE
            print(f"[DEBUG] Querying {stage} server ({ns_ip}) - SUCCESS")
            
            # If an answer is found, print and return
            if debug:
                print("***** BEGIN RESPONSE *****")
                print(response.to_text())
                print("***** END RESPONSE *****")
            if response.answer:
                cname = ""
                for i in response.answer:
                    if i.rdtype == dns.rdatatype.A:
                        print(f"[SUCCESS] {original_domain} -> {i[0]}")
                        return
                    elif i.rdtype == dns.rdatatype.CNAME:
                        cname = (i.to_text().split()[-1])
                if debug: print("maybe we got a CNAME response?")
                if debug: print(cname)
                cname = str(cname)
                if cname:
                    if cname[-1] == ".":
                        cname = cname[:-1]
                    domain = cname
                    next_ns_list = list(ROOT_SERVERS.keys())
                    stage = "ROOT"
                    # repeat the process without resetting ns_ip
                    continue
            elif response.authority:
                if debug: print("got response.authority")
            elif response.additional:
                if debug: print("got response.additional")
            else:
                if debug: print("empty response!!!")

            # If no answer, extract the next set of nameservers
            next_ns_list = extract_next_nameservers(response)
            # TODO: Move to the next resolution stage, i.e., it is either TLD, ROOT, or AUTH
            if stage == "ROOT":
                stage = "TLD"
            elif stage == "TLD":
                stage = "AUTH"
            else:
                if debug: print("***")
        else:
            next_ns_list = next_ns_list[1:]
            if ns_ip == []:
                print(f"[ERROR] Query failed for {stage} {ns_ip}")
                return  # Stop resolution if a query fails
            else:
                if debug: print(f"Trying remaining servers")
                continue;
    print("[ERROR] Resolution failed.")  # Final failure message if no nameservers respond

def recursive_dns_lookup(domain):
    """ 
    Performs recursive DNS resolution using the system's default resolver.
    This approach relies on a resolver (like Google DNS or a local ISP resolver)
    to fetch the result recursively.
    """
    print(f"[Recursive DNS Lookup] Resolving {domain}")
    try:
        # TODO: Perform recursive resolution using the system's DNS resolver
        # Notice that the next line is looping through, therefore you should have something like answer = ??
        response = send_dns_query("8.8.8.8", domain, recursive = True)
        answer = response.answer
        for rdata in answer:
            address = rdata[0]
            print(f"[SUCCESS] {domain} -> {address}")

    except Exception as e:
        print(f"[ERROR] Recursive lookup failed: {e}")  # Handle resolution failure

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3 or sys.argv[1] not in {"iterative", "recursive"}:
        print("Usage: python3 dns_server.py <iterative|recursive> <domain>")
        sys.exit(1)

    mode = sys.argv[1]  # Get mode (iterative or recursive)
    domain = sys.argv[2]  # Get domain to resolve
    start_time = time.time()  # Record start time
    
    while domain[-1] == "/":
        domain = domain[:-1]
    # Execute the selected DNS resolution mode
    if mode == "iterative":
        iterative_dns_lookup(domain)
    else:
        recursive_dns_lookup(domain)
    
    print(f"Time taken: {time.time() - start_time:.3f} seconds")  # Print execution time
