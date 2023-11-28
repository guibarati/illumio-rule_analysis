import ipaddress

def ipv4(address):
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv4Network(address, strict=False)
            return True
        except ValueError:
            return False


def ips_inrange(start_ip, end_ip):
    start_int = int(ipaddress.IPv4Address(start_ip))
    end_int = int(ipaddress.IPv4Address(end_ip))
    return max(end_int - start_int + 1, 0)



def ips_incidr(start_ip):
    network = ipaddress.ip_network(start_ip, strict=False)
    return network.num_addresses
