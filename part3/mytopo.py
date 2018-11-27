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
        s3 = self.addSwitch('s3', dpid="3")
        s4 = self.addSwitch('s4', dpid="4")
        h1 = self.addHost('h1', ip="10.0.1.2/24", defaultRoute="via 10.0.1.1")
        h2 = self.addHost('h2', ip="10.0.1.3/24", defaultRoute="via 10.0.1.1")
        h3 = self.addHost('h3', ip="10.0.1.4/24", defaultRoute="via 10.0.1.1")
        h4 = self.addHost('h4', ip="10.0.2.2/24", defaultRoute="via 10.0.2.1")
        h5 = self.addHost('h5', ip="10.0.2.3/24", defaultRoute="via 10.0.2.1")
        h6 = self.addHost('h6', ip="10.0.2.4/24", defaultRoute="via 10.0.2.1")
        h7 = self.addHost('h7', ip="10.0.3.2/24", defaultRoute="via 10.0.3.1")
        h8 = self.addHost('h8', ip="10.0.3.3/24", defaultRoute="via 10.0.3.1")
        h9 = self.addHost('h9', ip="10.0.3.4/24", defaultRoute="via 10.0.3.1")
        h10 = self.addHost('h10', ip="10.0.4.2/24", defaultRoute="via 10.0.4.1")
        h11 = self.addHost('h11', ip="10.0.4.3/24", defaultRoute="via 10.0.4.1")
        h12 = self.addHost('h12', ip="10.0.4.4/24", defaultRoute="via 10.0.4.1")
        # Add links
        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
        self.addLink( h3, s1 )
        self.addLink( h4, s2 )
        self.addLink( h5, s2 )
        self.addLink( h6, s2 )
        self.addLink( h7, s3 )
        self.addLink( h8, s3 )
        self.addLink( h9, s3 )
        self.addLink( h10, s4 )
        self.addLink( h11, s4 )
        self.addLink( h12, s4 )

        self.addLink( s1, s2 )
        self.addLink( s2, s3 )
        self.addLink( s2, s4 )

topos = { 'mytopo': ( lambda: MyTopo() ) }
