package se.sics.jipv6.analyzer;

import se.sics.jipv6.analyzer.NodeTable.NodeStats;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.MacPacket;
import se.sics.jipv6.mac.IEEE802154Handler;
import se.sics.jipv6.pcap.CapturedPacket;

public class MACAnalyzer implements PacketAnalyzer {

    NodeTable nodeTable;
    
     
    /* 802.15.4 stats */
    private int beacon;
    private int ack;
    private int data;
    private int cmd;
    
    private long bytes;

    @Override
    public void print() {
        long elapsed = nodeTable.getElapsed();
        System.out.printf("MAC Analyzer: 802154: DATA:%d ACK:%d CMD:%d BEACON:%d bytes:%d bytes/sec:%d\n",
                data, ack, cmd, beacon, bytes, bytes * 1000 / elapsed);
        
    }
    
    @Override
    public void init(NodeTable table) {
        nodeTable = table;
    }

    @Override
    public boolean analyzeRawPacket(CapturedPacket packet) {
        return true;
    }

    @Override
    public boolean analyzeMacPacket(MacPacket packet, Node sender,
            Node receiver) {
        int type = packet.getAttributeAsInt("802154.type");
        bytes += packet.getTotalLength() + 5 + 1 + 2; /* Preamble + len + crc */

        // Take the time of first packet as start time
        NodeStats stats = nodeTable.getNodeStats(sender);
        if (stats != null) {
            stats.sentBytes += packet.getTotalLength() + 5 + 1 + 2;
        }
        
        switch (type) {
        case IEEE802154Handler.BEACONFRAME:
            beacon++;
            if (stats != null) {
                stats.beacon++;
            }
            break;
        case IEEE802154Handler.ACKFRAME:
            ack++;
            if (nodeTable.printAck) {
                if(packet.getAttributeAsInt(IEEE802154Handler.SEQ_NO) == nodeTable.lastSeqNo) {
                    System.out.println("ACKED");
                    nodeTable.printAck = false;
                } else {
                    System.out.print("Wrong ack: " + nodeTable.lastSeqNo + " <> " + packet.getAttributeAsInt(IEEE802154Handler.SEQ_NO));
                }
            }
            break;
        case IEEE802154Handler.DATAFRAME:
            data++;
            if (stats != null) {
                stats.data++;
            }
            nodeTable.lastSeqNo = packet.getAttributeAsInt(IEEE802154Handler.SEQ_NO);
            break;
        case IEEE802154Handler.CMDFRAME:
            cmd++;
            break;
        }
        if (nodeTable.printAck) {
            System.out.println(" NO - ACK");
        }
        nodeTable.printAck = false;
        return true;
    }

    @Override
    public boolean analyzeIPPacket(IPv6Packet packet, Node macSender,
            Node macReceiver) {
        return true;
    }

}
