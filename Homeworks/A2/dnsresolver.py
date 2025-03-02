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
        # Recursion is specified via the RD bit in the header.
        if (recursive):
            query.flags |= dns.flags.RD
        else:
            query.flags &= ~(dns.flags.RD)

        # TODO 1
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

    """
    Possibilities:
        - The final answer is present in the response: then iterative_dns_lookup()
          does not call this function.
        - The response has the name of the TLD/authoritative server under 
          response.authority. Extract the names
        - response.additional may have the IP addresses for the above names,
          but sometimes we need to find the name ourselves. In that case, use 
          the DNS library's helper.
    """
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for rr in rrset:
                ns_name = rr.to_text()
                ns_names.append(ns_name)  # Extract nameserver hostname
                print(f"Extracted NS hostname: {ns_name}")

    ## OUR CHANGES BEGIN HERE !!!
        elif rrset.rdtype == dns.rdatatype.SOA:
            # found this in some websites. But these websites are restricted to 
            # other LANs.

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
            # Canonical names: this will be handled by the upper-level function.
            if debug:
                print("CNAME")


    # extract ip addresses. check that they belong to the required TLD/AUTH servers
    for rrset in response.additional:
        name = rrset.to_text()
        ipversion = name.split()[3]
        # using asserts to check that we have the right field
        # ipversion is A for IPv4, AAAA for IPv6, might have some other values
        assert(ipversion in ["AAAA", "A",  "MX", "CNAME"])
        # skip IPv6 addresses
        if ipversion == "AAAA":
            continue

        address = name.split()[-1]
        assert(address[0].isdigit() and address[-1].isdigit() and address.count('.') == 3)

        # get the resource record
        # confirm that it is a NS we want
        rr = rrset[0]
        address = rr.to_text()
        name = rrset.name.to_text()
        if (name in ns_names):
            ns_ips.append(address)
            print(f"Resolved {name} to {address}")

    # sometimes, there is no iP address in the response. find it manually
    # for eahc nameserver
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
    ### DONE ABOVE

    
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

    # loop over stages of resolution
    # At each stage, next_ns_list is the list of servers to try.
    # when one of them succeeds, we replace the list with the next stage's list
    # when there is a failure, we remove it from the list and retry
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
            # if we are lucky, we have the exact answer by now
            # or, we have the cname
            if response.answer:
                cname = ""
                # success is true if >=1 of the RRs is correct. don't exit directly
                #  because there might be multiple IP addresses for one domain (aliasing)
                # so, we will set success = 1 and exit AFTER the for loop
                success = False

                for i in response.answer:
                    if debug: print(i)
                    if i.rdtype == dns.rdatatype.A:
                        print(f"[SUCCESS] {original_domain} -> {i[0]}")
                        success = True
                    elif i.rdtype == dns.rdatatype.CNAME:
                        cname = (i.to_text().split()[-1])

                # found a answer
                if success:
                    return
                if debug: print("maybe we got a CNAME response?")
                if debug: print(cname)
                cname = str(cname)
                # if we are here, we did NOT get any answer but got some CNAME
                # restart resolution from root with the new name
                if cname:
                    if cname[-1] == ".":
                        cname = cname[:-1]
                    domain = cname
                    next_ns_list = list(ROOT_SERVERS.keys())
                    stage = "ROOT"
                    # repeat the process without resetting ns_ip
                    continue

            # all these are handled by extract_next_nameservers()
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
            # failure: try the next server
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
