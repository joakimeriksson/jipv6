package se.sics.jipv6.analyzer;

import java.io.PrintStream;
import java.util.Formatter;

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


    private Formatter out;

    @Override
    public void print() {
        long elapsed = nodeTable.getElapsed(null);
        // Use one second if less has elapsed
        if (elapsed < 1000) {
            elapsed = 1000;
        }
        out.format("MAC Analyzer: 802154: DATA:%d ACK:%d CMD:%d BEACON:%d bytes:%d bytes/sec:%d\n",
                data, ack, cmd, beacon, bytes, bytes * 1000 / elapsed);
    }

    @Override
    public void init(NodeTable table, Formatter out) {
        this.nodeTable = table;
        this.out = out;
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
        long elapsed = nodeTable.getElapsed(packet);
        // Take the time of first packet as start time
        NodeStats stats = nodeTable.getNodeStats(sender);
        if (stats != null) {
            stats.sentBytes += packet.getTotalLength() + 5 + 1 + 2;
        }

        switch (type) {
        case IEEE802154Handler.BEACONFRAME:
            printStart(out, packet, elapsed);
            beacon++;
            out.format("Beacon Frame from:" + sender.macAddresses.get(0) + "\n");
            if (stats != null) {
                stats.beacon++;
            }
            break;
        case IEEE802154Handler.ACKFRAME:
            ack++;
            if (nodeTable.printAck) {
                if(packet.getAttributeAsInt(IEEE802154Handler.SEQ_NO) == nodeTable.lastSeqNo) {
                    out.format(" ACKED\n");
                    nodeTable.printAck = false;
                } else {
                    out.format(" Wrong ack: " + nodeTable.lastSeqNo + " <> " + packet.getAttributeAsInt(IEEE802154Handler.SEQ_NO));
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
            printStart(out, packet, elapsed);
            out.format("Beacon Request\n");
            cmd++;
            break;
        }
        if (nodeTable.printAck) {
            out.format(" NO - ACK\n");
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
