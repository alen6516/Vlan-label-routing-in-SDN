#from line_topo import host_number

import logging

host_number=6

logging.basicConfig(filename='mapping.log', filemode='w', level=logging.DEBUG)
LOG=logging.getLogger('mapping_log')

LOG.info('host_number = %d' % host_number)

protocol='icmp'

ip_list=[]
mac_list=[]
mapping_list=[]
host_list=[]

class compact_entry():
    def __init__(self, protocol, src_ip, src_mac, dst_ip, dst_mac, vlan):
        self.protocol=protocol
        self.src_ip=src_ip
        self.src_mac=src_mac
        self.dst_ip=dst_ip
        self.dst_mac=dst_mac
        self.vlan=vlan

class host():
    def __init__(self, ip, mac):
        self.ip=ip
        self.mac=mac


for i in range(1,host_number+1):
    
    src_ip='10.0.0.%s' % i
    if i>9:
        src_mac='00:00:00:00:00:%s' % i
    else:
        src_mac='00:00:00:00:00:0%s' % i

    ip_list.append(src_ip)
    mac_list.append(src_mac)
    host_list.append(host(src_ip, src_mac))

    for j in range(1,host_number+1):
        dst_ip='10.0.0.%s' % j

        if j>9:
            dst_mac='00:00:00:00:00:%s' % j
        else:
            dst_mac='00:00:00:00:00:0%s' % j
            

        vlan='%s%s' % (i,j)

        entry = compact_entry(protocol, src_ip, src_mac, dst_ip, dst_mac, vlan)

        mapping_list.append(entry)

for entry in mapping_list:
    LOG.info('vlan=%s, protocol=%s, src_ip=%s, src_mac=%s, dst_ip=%s, dst_mac=%s' % (entry.vlan, entry.protocol, entry.src_ip, entry.src_mac, entry.dst_ip, entry.dst_mac))


print([ip for ip in ip_list])
print([mac for mac in mac_list])
print([(host.ip,host.mac) for host in host_list])


