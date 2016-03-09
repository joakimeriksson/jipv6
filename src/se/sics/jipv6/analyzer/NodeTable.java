package se.sics.jipv6.analyzer;
import java.util.HashMap;

import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.Packet;

public class NodeTable {
    public HashMap<String, Node> nodeTable = new HashMap<String,Node>();

    public Node getNodeByMAC(byte[] mac) {
        String addr = Packet.macToString(mac);
        Node node = nodeTable.get(addr);
        if (node == null) {
            node = new Node();
            node.macAddresses.add(addr);
            nodeTable.put(addr, node);
        }
        return node;
    }
    
    public Node getNodeByIP(byte[] address) {
        String addr = IPv6Packet.addressToString(address);
        return nodeTable.get(addr);
    }

    public void print() {
        for(Node node : nodeTable.values()) {
            node.print();
        }
    }

    public void addIPAddr(Node node, byte[] address) {
        if (getNodeByIP(address) == null) {
            String addrStr;
            nodeTable.put(addrStr = IPv6Packet.addressToString(address),node);
            node.ipAddresses.add(addrStr);
        }
    }
    
}
