from pysnmp.hlapi import *
from scapy.all import *
import ipaddress

def snmp_walk(ip, oid):
    origin = oid
    results = []
    while oid.startswith(origin):
        snmp_iterator = nextCmd(SnmpEngine(),
                        CommunityData('PSIPUB'),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)))
        errorIndication, errorStatus, errorIndex, varBinds = next(snmp_iterator)
        if errorIndication:
            break
        else:
            for varBind in varBinds:
                oid = varBind[0].getOid().prettyPrint()
                if oid.startswith(origin):
                    results.append(varBind[-1].prettyPrint())
    return results


current_ip = conf.route.route('0.0.0.0')[2]
own_addresses_oid = '1.3.6.1.2.1.4.20.1.1'
route_addresses_oid = '1.3.6.1.2.1.4.21.1.1'
route_masks_oid = '1.3.6.1.2.1.4.21.1.11'
route_hops_oid = '1.3.6.1.2.1.4.21.1.7'
been_through_ips = []
todo_ips = []
found_networks = []


print('Starting network topology analysis at:', conf.route.route('0.0.0.0')[1])
print('Default gateway:', current_ip)
todo_ips.append(current_ip)

while len(todo_ips) > 0:
    current_ip = todo_ips.pop(0)
    
    ips = snmp_walk(current_ip, own_addresses_oid)
    if len(ips) == 0:
        continue
    been_through_ips += ips
    print("This router's addresses:\n", ips)
    
    routes = snmp_walk(current_ip, route_addresses_oid)
    masks = snmp_walk(current_ip, route_masks_oid)
    networks = []
    for i in range(0, len(routes)):
        network = ipaddress.IPv4Network(f'{routes[i]}/{masks[i]}', strict=False)
        if network.prefixlen == 0 or network.prefixlen == 32:
            continue
        network_string = f'{network.network_address}/{network.prefixlen}'
        if network_string not in found_networks:
            networks.append(network_string)
    
    found_networks += networks
    print('New networks:\n', networks)
    
    hops = snmp_walk(current_ip, route_hops_oid)
    for hop in hops:
        if hop not in been_through_ips:
            todo_ips.append(hop)
    
    if len(todo_ips) > 0:
        print('--------')

print('Analysis finished.')

