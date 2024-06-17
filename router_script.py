import getpass
import telnetlib

def get_hosts():
    hosts = []
    with open("vm8_IP.txt") as vm:
        for vm8 in vm:
            hosts.append(vm8.strip())
    return hosts

def get_netmask(block):
    block = int(block)
    mask = (0xffffffff >> (32 - block)) << (32 - block)
    netmask = str((0xff000000 & mask) >> 24)   + '.' + str((0x00ff0000 & mask) >> 16)   + '.' + str((0x0000ff00 & mask) >> 8) + '.' + str((0x000000ff & mask))
    return netmask

def ip_and_netmask(router):
    ip_addresses = []
    netmasks = []
    with open("routerIP.txt", encoding="utf8") as f:
        for line in f:
            if line.startswith(router):
                addresses = line.split(':')[1].strip()
                ip_addresses_with_blocks = addresses.split(', ')
                for ip in ip_addresses_with_blocks:
                    ip_addresses.append(ip.split('/')[0])
                    netmasks.append(get_netmask(ip.split('/')[1]))
    return ip_addresses, netmasks

def get_network(ips):
    network = []
    for ip in ips:
        tmp_ip = ip.split('.')
        tmp_ip[-1] = '0'
        network_ip = ""
        for i in range(len(tmp_ip)):
            network_ip += tmp_ip[i] + '.'
        network.append(network_ip[:-1])
    return network

def get_wildcard(netmasks):
    wildcard = []
    default = ["255","255","255","255"]
    for mask in netmasks:
        tmp_mask = mask.split('.')
        tmp_wildcard = []
        for i in range(len(tmp_mask)):
            tmp_wildcard.append(str(int(default[i]) - int(tmp_mask[i])))
        wildcard.append(".".join(tmp_wildcard))
    return wildcard

def get_router_id(id):
    return id + "." + id + "." + id + "." + id

def basic_config(Telnet, router):
    Telnet.write(b"config t\n")
    Telnet.read_until(b"#")
    Telnet.write(f"hostname {router}\n".encode("ascii"))
    Telnet.read_until(b"#")
    Telnet.write(b"no ip domain-lookup\n")
    Telnet.read_until(b"#")
    Telnet.write(b"enable secret class\n")
    Telnet.read_until(b"#")
    Telnet.write(b"line console 0\n")
    Telnet.read_until(b"#")
    Telnet.write(b"password cisco\n")
    Telnet.read_until(b"#")
    Telnet.write(b"login\n")
    Telnet.read_until(b"#")
    print("Console password and enable login")
    Telnet.write(b"exit\n")
    Telnet.read_until(b"#")
    Telnet.write(b"service password-encryption\n")
    Telnet.read_until(b"#")
    print("Encrypted plaintext passwords")
    Telnet.write(b"banner motd #Unauthorized access is prohibited!#\n")
    Telnet.read_until(b"#")
    print("Banner created\n")
    Telnet.write(b"end\n")
    Telnet.read_until(b"#")

def interface_config(Telnet, router):
    Telnet.write(b"config t\n")
    Telnet.read_until(b"#")
    ipv4 = ip_and_netmask(router)
    ip, netmask = ipv4[0], ipv4[1]
    for i in range(len(ip)):
        Telnet.write(f"int g0/{i}\n".encode("ascii"))
        Telnet.read_until(b"#")
        Telnet.write(f"ip add {ip[i]} {netmask[i]}\n".encode("ascii"))
        Telnet.read_until(b"#")
        Telnet.write(b"no shutdown\n")
        Telnet.read_until(b"#")
    Telnet.write(b"end\n")
    Telnet.read_until(b"#")
    print("IP interfaces created\n")  

def routing_protocol(Telnet, router, id):    
    ipv4 = ip_and_netmask(router)
    ip, netmask = ipv4[0], ipv4[1]
    network = get_network(ip)
    wildcard = get_wildcard(netmask)

    router_id = get_router_id(id)

    print(f"Networks: {network}")
    print(f"Wildcards: {wildcard}")

    Telnet.write(b"config t\n")
    Telnet.read_until(b"#")
    Telnet.write(b"router ospf 10\n")
    for i in range(len(network)):
        Telnet.read_until(b"#")
        Telnet.write(f"router-id {router_id}\n".encode("ascii"))
        print("Router id " + router_id + " implemented")
        Telnet.read_until(b"#")
        command = f"network {network[i]} {wildcard[i]} area 0\n"
        Telnet.write(command.encode("ascii"))
        response = Telnet.read_until(b"#")
        if b"#" not in response:
            print(f"Failed to apply network command: {command}")
            return
        else:
            print(f"Successfully applied network command: {command}")
    print("OSPF implemented\n")


def main(host, id_router, user, password):
    router = "R" + id_router
    try:
        with telnetlib.Telnet(host) as telnet:
            telnet.read_until(b"Username: ")
            telnet.write(user.encode('ascii') + b"\n")
            if password:
                telnet.read_until(b"Password: ")
                telnet.write(password.encode('ascii') + b"\n")
            telnet.read_until(b"#") 
            basic_config(telnet, router)
            interface_config(telnet, router)
            routing_protocol(telnet, router, id_router)
            
            telnet.write(b"end\n")
            telnet.read_until(b"#")

            print("Saving configuration...")
            telnet.write(b"write\n")
            telnet.read_until(b"#")
            print("Configuration saved successfully.\n")
    except Exception as e:
        print(e)

if __name__ == '__main__':
    HOSTS = get_hosts()
    user = input("Enter your remote account: ")
    password = getpass.getpass()
    id_router = 0

    for host in HOSTS:
        id_router += 1
        main(host, str(id_router), user, password)

