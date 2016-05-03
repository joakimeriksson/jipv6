package se.sics.jipv6.analyzer;
import java.io.PrintWriter;
import java.util.HashMap;

import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.MacPacket;

public class NodeTable {
    private final HashMap<String, Node> nodeTable = new HashMap<String,Node>();

    private long startTime;

    public boolean printAck;
    public int lastSeqNo;

    public static class NodeStats {
        /* MAC stats */
        int sentBytes;
        int beacon;
        int data;
        long lastReq;
        double avgResponse;

        public String toString() {
            return "Sent Bytes:" + sentBytes + " Beacon:" + beacon + " Data:" + data;
        }
    }

    public NodeStats getNodeStats(Node src) {
        NodeStats stats = null;
        if (src != null) {
            stats = (NodeStats) src.properties.get("nodeStats");
            if (stats == null) {
                stats = new NodeStats();
                src.properties.put("nodeStats", stats);
            }
        }
        return stats;
    }


    public long getElapsed() {
        if (startTime == 0) {
            startTime = System.currentTimeMillis();
        }
        return System.currentTimeMillis() - startTime;
    }

    public Node getNodeByMAC(byte[] mac) {
        String addr = MacPacket.macToString(mac);
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

    public void print(PrintWriter printWriter) {
        for(String key : nodeTable.keySet()) {
            Node node = nodeTable.get(key);
            if (key.length() < 24) {
                /* A MAC address - shorter then IPv6 address... */
                node.print(printWriter);
            }
        }
    }

    public void addIPAddr(Node node, byte[] address) {
        if (getNodeByIP(address) == null) {
            String addrStr;
            nodeTable.put(addrStr = IPv6Packet.addressToString(address),node);
            node.ipAddresses.add(addrStr);
        }
    }


    public int nodeCount() {
        return nodeTable.size();
    }


    public Node[] getAllNodes() {
        // TODO Auto-generated method stub
        HashMap<Node, Node> uniqueMap = new HashMap<Node, Node>();
        Node[] nodes = nodeTable.values().toArray(new Node[0]);
        System.out.println("Started with: " + nodes.length);
        for (int i = 0; i < nodes.length; i++) {
            Node n = nodes[i];
            if (!uniqueMap.containsKey(n)) {
                uniqueMap.put(n,n);
            }
        }
        nodes = uniqueMap.values().toArray(new Node[0]);
        System.out.println("ended with: " + nodes.length);
        return nodes;
    }
}
