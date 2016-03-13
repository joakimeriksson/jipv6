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

    static class NodeStats {
        /* MAC stats */
        int sentBytes;
        int cmd;
        int beacon;
        int data;
        long lastReq;
        double avgResponse;
        
        public String toString() {
            return "Sent Bytes:" + sentBytes + " Beacon:" + beacon + " Cmd:" + cmd + " Data:" + data;
        }
    }
    
    class SleepStats {
        int sleepSessions; /* number of detected sleep sessions */
        int sleepReports;
        long lastReportTime;
        double avgReport2ResponseTime;
        public int noPacket;
        public int packet;

        public String toString() {
            return "Sleep sessions:" + sleepSessions + " sleepReports:" + sleepReports + " AvgRepRespTime:" + avgReport2ResponseTime;
        }
    }
    
    
    /* used for adding specific data per node */
    private NodeTable nodeTable;
    private int lastSeqNo;
    private boolean printAck;
    

    public void init(NodeTable table) {
        this.nodeTable = table;
    }
    
    public void print() {
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed < 1) {
            elapsed = 1;
        }
        System.out.printf("Tot:%d DIO:%d ucDIS:%d mcDIS:%d DAO:%d NS:%d Sleep:%d Data:%d 802154: DATA:%d ACK:%d CMD:%d BEACON:%d bytes:%d bytes/sec:%d\n",
                totPacket,
                dioPacket, ucDISPacket, bcDISPacket,
                daoPacket, nsPacket, sleepPacket, dataPacket,
                data, ack, cmd, beacon, bytes, bytes * 1000 / elapsed);
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

    
    /* MAC packet received */
    public void analyzePacket(Packet packet, Node src, Node dst) {
        int type = packet.getAttributeAsInt("802154.type");
        bytes += packet.getTotalLength() + 5 + 1 + 2; /* Preamble + len + crc */

        // Take the time of first packet as start time
        if (startTime == 0) {
            startTime = packet.getTimeMillis();
        }

        NodeStats stats = getNodeStats(src);
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
        long responseTime = 0;
        Node sourceNode = nodeTable.getNodeByIP(packet.getSourceAddress());
        Node destNode = nodeTable.getNodeByIP(packet.getDestinationAddress());
        IPPayload payload = packet.getIPPayload();
        totPacket++;
        // Take the time of first packet as start time
        if (startTime == 0) {
            startTime = packet.getTimeMillis();
        }
        long elapsed = packet.getTimeMillis() - startTime;
        String timeStr = String.format("%d:%02d:%02d.%03d %3d", elapsed / (1000 * 3600) , elapsed / (1000 * 60) % 60,
                (elapsed / 1000) % 60, elapsed % 1000, packet.getTotalLength());
        
        if (destNode != null) {
            NodeStats stats = getNodeStats(destNode);
            if (stats != null) {
                stats.lastReq = System.currentTimeMillis();
            }
        }
        if (sourceNode != null) {
            NodeStats stats = getNodeStats(sourceNode);
            if (stats != null) {
                if(System.currentTimeMillis() - stats.lastReq < 1000) {
                    responseTime = System.currentTimeMillis() - stats.lastReq;
//                    System.out.println("**** Response within " + (System.currentTimeMillis() - stats.lastReq));
                }
            }
        }

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
                    if (sourceNode != null) {
                        SleepStats sleepInfo = (SleepStats) sourceNode.properties.get("sleepInfo");
                        if (sleepInfo == null) {
                            sourceNode.properties.put("sleepInfo", sleepInfo = new SleepStats());
                        }
                        sleepInfo.sleepSessions++;
                    }
                    System.out.printf("[%s] Sleep Awake in %d: Flag: %02x Dir:%s ",
                            timeStr, time, flag, (flag & 0x80) > 0 ? "D" : "U");
                } else if ((flag & 0xf) == 0x02) {
                    if (destNode != null) {
                        SleepStats sleepInfo = (SleepStats) destNode.properties.get("sleepInfo");
                        if (sleepInfo != null) {
                            sleepInfo.sleepReports++;
                            sleepInfo.noPacket++;
                        }
                    }
                    System.out.printf("[%s] Sleep Report - no packet recived Flag: %02x Dir:%s ",
                            timeStr, flag, (flag & 0x80) > 0 ? "D" : "U");

                } else if ((flag & 0xf) == 0x03) {
                    System.out.printf("[%s] Sleep Report - packet recived Flag: %02x Dir:%s HoldTime: %d ",
                            timeStr, flag, (flag & 0x80) > 0 ? "D" : "U", time);
                    if (destNode != null) {
                        SleepStats sleepInfo = (SleepStats) destNode.properties.get("sleepInfo");
                        if (sleepInfo != null) {
                            sleepInfo.packet++;
                            sleepInfo.lastReportTime = packet.getTimeMillis();
                        }
                    }
                }
                sleepPacket++;
            } else {
                dataPacket++;
                printAck = true;
                System.out.printf("[%s] *** UDP Message to ", timeStr);
                IPv6Packet.printAddress(System.out, packet.getDestinationAddress());
                System.out.print(" from: ");
                IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                System.out.print(" " + (responseTime > 0 ? responseTime + " " : ""));
                if (sourceNode != null) {                    
                    SleepStats sleepInfo = (SleepStats) sourceNode.properties.get("sleepInfo");
                    if (sleepInfo != null) {
                        long elapsedTime = packet.getTimeMillis() - sleepInfo.lastReportTime;
                        if(elapsedTime < 1000) {
                            System.out.printf(" Sleepy Node. Time since report: %d avg: %f ",
                                    elapsedTime, sleepInfo.avgReport2ResponseTime);
                            if(sleepInfo.avgReport2ResponseTime == 0) {
                                sleepInfo.avgReport2ResponseTime = elapsedTime;
                            } else {
                                sleepInfo.avgReport2ResponseTime = (sleepInfo.avgReport2ResponseTime * 9.0 + 
                                        elapsedTime) / 10.0;
                            }
                        } else {
                            System.out.printf(" Sleepy Node. Long Time since report: %d avg: %f ",
                                    elapsedTime, sleepInfo.avgReport2ResponseTime);                            
                        }
                    }
                }
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
                String mCast = IPv6Packet.isLinkLocal(packet.getDestinationAddress()) ? "UC" : "MC";
                System.out.printf("[%s] DIO (" + mCast + ") from: ", timeStr);
                IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                System.out.print(" ");
                rpl.printPacket(System.out);
                break;
            case RPLPacket.RPL_DAO:
                daoPacket++;
                rpl.printPacket(System.out);
                System.out.println();
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
