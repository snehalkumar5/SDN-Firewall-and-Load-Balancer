from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch, IVSSwitch, UserSwitch
from mininet.link import Link, TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.util import *
if __name__ == "__main__":
    setLogLevel('info')
    #net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)
    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')
    print( '*** Adding controller\n' )
    c = net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)
    # Create hosts here
    print("Creating hosts")
    h1 = net.addHost( 'h1', mac='00:00:00:00:00:01', ip='10.0.0.1/8' )
    h2 = net.addHost( 'h2', mac='00:00:00:00:00:02', ip='10.0.0.2/8' )
    h3 = net.addHost( 'h3', mac='00:00:00:00:00:03', ip='10.0.0.3/8' )
    h4 = net.addHost( 'h4', mac='00:00:00:00:00:04', ip='10.0.0.4/8' )
    h5 = net.addHost( 'h5', mac='00:00:00:00:00:05', ip='10.0.0.5/8' )
    h6 = net.addHost( 'h6', mac='00:00:00:00:00:06', ip='10.0.0.6/8' )
    h7 = net.addHost( 'h7', mac='00:00:00:00:00:07', ip='10.0.0.7/8' )

    # Create switches here
    print("Creating switches")
    s1 = net.addSwitch( 's1' )
    s2 = net.addSwitch( 's2' )
    s3 = net.addSwitch( 's3' )
    s4 = net.addSwitch( 's4' )
    s5 = net.addSwitch( 's5' )

    # Add links here
    print("Adding links")
    net.addLink(h1, s2)
    net.addLink(h2, s4)
    net.addLink(h3, s4)
    net.addLink(s4, s2)
    net.addLink(s2, s1)
    net.addLink(h4, s3)
    net.addLink(h5, s5)
    net.addLink(h6, s5)
    net.addLink(h7, s5)
    net.addLink(s5, s3)
    net.addLink(s3, s1)

    print("Starting network")
    #c = net.addController('c', controller=RemoteController)
    net.start()
    print("Dumping host connections")
    dumpNodeConnections(net.hosts)
    print("Starting CLI")
    CLI(net)
    print("Ending execution")
    net.stop()
