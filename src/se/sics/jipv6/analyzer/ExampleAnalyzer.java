package se.sics.jipv6.analyzer;

import se.sics.jipv6.core.ICMP6Packet;
import se.sics.jipv6.core.IPPayload;
import se.sics.jipv6.core.IPv6ExtensionHeader;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.Packet;
import se.sics.jipv6.core.RPLPacket;
import se.sics.jipv6.core.UDPPacket;
import se.sics.jipv6.mac.IEEE802154Handler;

public class ExampleAnalyzer implements PacketAnalyzer {

    private static final boolean DEBUG = false;
    private int dioPacket;
    private int bcDISPacket;
    private int ucDISPacket;
    private int dataPacket;
    private int sleepPacket;
    private int daoPacket;
    private int nsPacket;
    private int totPacket;
        
    /* 802.15.4 stats */
    private int beacon;
    private int ack;
    private int data;
    private int cmd;
    
    private long bytes;
    private long startTime;

    class NodeStats {
        /* MAC stats */
        int sentBytes;
        int cmd;
        int beacon;
        int data;
        
        public String toString() {
            return "Sent Bytes:" + sentBytes + " Beacon:" + beacon + " Cmd:" + cmd + " Data:" + data;
        }
    }
    
    /* used for adding specific data per node */
    private NodeTable nodeTable;
    private int lastSeqNo;
    private boolean printAck;
    

    public void init(NodeTable table) {
        this.nodeTable = table;
        startTime = System.currentTimeMillis();
    }
    
    public void print() {
        System.out.printf("Tot:%d DIO:%d ucDIS:%d mcDIS:%d DAO:%d NS:%d Sleep:%d Data:%d 802154: DATA:%d ACK:%d CMD:%d BEACON:%d bytes:%d bytes/sec:%d\n",
                totPacket,
                dioPacket, ucDISPacket, bcDISPacket,
                daoPacket, nsPacket, sleepPacket, dataPacket,
                data, ack, cmd, beacon, bytes, bytes * 1000 / (System.currentTimeMillis() - startTime));
    }
    
    /* MAC packet received */
    public void analyzePacket(Packet packet, Node src, Node dst) {
        int type = packet.getAttributeAsInt("802154.type");
        bytes += packet.getTotalLength() + 5 + 1 + 2; /* Preamble + len + crc */
        NodeStats stats = null;
        if (src != null) {
            stats = (NodeStats) src.properties.get("nodeStats");
            if (stats == null) {
                stats = new NodeStats();
                src.properties.put("nodeStats", stats);
            }
            if (stats != null) {
                stats.sentBytes += packet.getTotalLength() + 5 + 1 + 2;
            }
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
            if (printAck) {
                if(packet.getAttributeAsInt(IEEE802154Handler.SEQ_NO) == lastSeqNo) {
                    System.out.println("ACKED");
                    printAck = false;
                } else {
                    System.out.print("Wrong ack: " + lastSeqNo + " <> " + packet.getAttributeAsInt(IEEE802154Handler.SEQ_NO));
                }
            }
            break;
        case IEEE802154Handler.DATAFRAME:
            data++;
            if (stats != null) {
                stats.data++;
            }
            lastSeqNo = packet.getAttributeAsInt(IEEE802154Handler.SEQ_NO);
            break;
        case IEEE802154Handler.CMDFRAME:
            cmd++;
            if (stats != null) {
                stats.cmd++;
            }
            break;
        }
        if (printAck) {
            System.out.println(" NO - ACK");
        }
        printAck = false;
    }
    
    /* IPv6 packet received */
    public void analyzeIPPacket(IPv6Packet packet) {
        IPPayload payload = packet.getIPPayload();
        totPacket++;
        // Adjust the start time if the packet was sent earlier (read from a log file)
        if (packet.getTimeMillis() < startTime) {
            startTime = packet.getTimeMillis();
        }
        long elapsed = packet.getTimeMillis() - startTime;
        String timeStr = String.format("%d:%02d:%02d.%03d", elapsed / (1000 * 3600) , elapsed / (1000 * 60) % 60, (elapsed / 1000) % 60, elapsed % 1000);
                
        while (payload instanceof IPv6ExtensionHeader) {
            if (DEBUG) {
                System.out.print("Analyzer - EXT HDR " + payload.getClass().getSimpleName() + ": ");
                payload.printPacket(System.out);
            }
            payload = ((IPv6ExtensionHeader) payload).getNext();
        }
        if (payload instanceof UDPPacket) {
            byte[] data = ((UDPPacket) payload).getPayload();

            if (IPv6Packet.isLinkLocal(packet.getDestinationAddress())) {
                printAck = true;
                System.out.print("*** Link Local Message: Possibly Sleep from ");
                IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                System.out.print(" to ");
                IPv6Packet.printAddress(System.out, packet.getDestinationAddress());
                System.out.println();
                int flag = data[4] & 0xff;
                int time = (data[6] & 0xff) * 256 + (data[7] & 0xff);
                if((flag & 0xf) == 0x01) {
                    System.out.printf("[%s] Sleep Awake in %d: Flag: %02x Dir:%s ",
                            timeStr, time, flag, (flag & 0x80) > 0 ? "D" : "U");
                } else if ((flag & 0xf) == 0x02) {
                    System.out.printf("[%s] Sleep Report - no packet recived Flag: %02x Dir:%s ",
                            timeStr, flag, (flag & 0x80) > 0 ? "D" : "U");
                } else if ((flag & 0xf) == 0x03) {
                    System.out.printf("[%s] Sleep Report - packet recived Flag: %02x Dir:%s HoldTime: %d ",
                            timeStr, flag, (flag & 0x80) > 0 ? "D" : "U", time);
                }
                sleepPacket++;
            } else {
                dataPacket++;
                System.out.printf("[%s] *** Message to/from DM Server from: ", timeStr);
                IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                System.out.println();
            }
        } else if (payload instanceof RPLPacket) {
            RPLPacket rpl = (RPLPacket) payload;
            switch (rpl.getCode()) {
            case RPLPacket.RPL_DIS:
                if (IPv6Packet.isLinkLocal(packet.getDestinationAddress())) {
                    /* ... */
                    printAck = true;
                    System.out.printf("[%s] *** Probe or repair from: ", timeStr);
                    IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                    System.out.print(" ");
                    ucDISPacket++;
                } else {
                    System.out.printf("[%s] *** Warning - broadcast DIS!!! from: ", timeStr);
                    IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                    System.out.println();
                    bcDISPacket++;
                }
                break;
            case RPLPacket.RPL_DIO:
                dioPacket++;
                break;
            case RPLPacket.RPL_DAO:
                daoPacket++;
                break;
            }
        } else if (payload instanceof ICMP6Packet) {
            ICMP6Packet icmp6 = (ICMP6Packet) payload;
            if (icmp6.getType() == ICMP6Packet.NEIGHBOR_SOLICITATION) {
                System.out.print("*** Warning - Neighbor solicitation!!! from: ");
                IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                System.out.println();
                nsPacket++;
            } else {
            }
        }
    }
}
