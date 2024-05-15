from mininet.net import Mininet
from mininet.node import Host, Switch

def my_network():
    net = Mininet(topo=LinearTopo())
    net.start()

    # Add your code to interact with the network here

    net.stop()

if __name__ == '__main__':
    my_network()
