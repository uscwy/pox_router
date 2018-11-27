"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        s1 = self.addSwitch('s1', dpid="1")
        s2 = self.addSwitch('s2', dpid="2")
        h3 = self.addHost('h3', ip="10.0.1.2/24", defaultRoute="via 10.0.1.1")
        h4 = self.addHost('h4', ip="10.0.1.3/24", defaultRoute="via 10.0.1.1")
        h5 = self.addHost('h5', ip="10.0.2.2/24", defaultRoute="via 10.0.2.1")
        # Add links
        self.addLink( h3, s1 )
        self.addLink( h4, s1 )
        self.addLink( h5, s2 )
        self.addLink( s1, s2 )

topos = { 'mytopo': ( lambda: MyTopo() ) }
