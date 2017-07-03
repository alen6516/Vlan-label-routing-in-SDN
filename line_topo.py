"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

host_number=6
'''
mac_list=[]
for i in range(1,host_number+1):
    mac_list.append('00:00:00:00:00:0%s' % i)
'''
class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )
               
        hosts=[]
        switch_number=3
        switches=[]        
        links=[]
        split=host_number//2

        for i in range(1,switch_number+1):
            switches.append(self.addSwitch('s%s' % i, dpid='%s' % i))            


        for i in range(1,host_number+1):
            hosts.append(self.addHost('h%s' % i))
        
        for i in range(1,switch_number):
            self.addLink(switches[i-1], switches[i])    
    
        for i in range(split):
            links.append(self.addLink(hosts[i], switches[0]))
        for i in range(split,host_number):
            links.append(self.addLink(hosts[i], switches[-1]))

topos = { 'mytopo': ( lambda: MyTopo() ) }
