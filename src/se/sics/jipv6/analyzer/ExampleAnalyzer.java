package se.sics.jipv6.analyzer;

import java.io.PrintStream;

import se.sics.jipv6.analyzer.NodeTable.NodeStats;
import se.sics.jipv6.core.ICMP6Packet;
import se.sics.jipv6.core.IPPayload;
import se.sics.jipv6.core.IPv6ExtensionHeader;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.MacPacket;
import se.sics.jipv6.core.UDPPacket;
import se.sics.jipv6.pcap.CapturedPacket;

public class ExampleAnalyzer implements PacketAnalyzer {

    private static final boolean DEBUG = false;
   
    private int dataPacket;
    private int sleepPacket;
    private int nsPacket;
    private int totPacket;
        

    private long startTime;
    
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

    public void init(NodeTable table) {
        this.nodeTable = table;
    }
    
    public void print() {
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed < 1) {
            elapsed = 1;
        }
        System.out.printf("Example Analyzer: Tot:%d NS:%d Sleep:%d Data:%d\n",
                totPacket,
                nsPacket, sleepPacket, dataPacket);
    }

    public void printFromTo(PrintStream out, IPv6Packet packet) {
        out.print("from ");
        IPv6Packet.printAddress(out, packet.getSourceAddress());
        out.print(" to ");
        IPv6Packet.printAddress(out, packet.getDestinationAddress());
    }
    
    /* MAC packet received */
    public boolean analyzeMacPacket(MacPacket packet, Node src, Node dst) {
        /* allow other analyzers to continue */
        return true;
    }
    
    /* IPv6 packet received */
    public boolean analyzeIPPacket(IPv6Packet packet, Node macSource, Node macDestination) {
        long responseTime = 0;
        Node sourceNode = nodeTable.getNodeByIP(packet.getSourceAddress());
        Node destNode = nodeTable.getNodeByIP(packet.getDestinationAddress());
        IPPayload payload = packet.getIPPayload();
        totPacket++;
        // Take the time of first packet as start time
        long elapsed = nodeTable.getElapsed();
        String timeStr = String.format("%d:%02d:%02d.%03d %3d", elapsed / (1000 * 3600) , elapsed / (1000 * 60) % 60,
                (elapsed / 1000) % 60, elapsed % 1000, packet.getTotalLength());
        
        /* Unicast messages are assumed to be requests / replies */
        if (destNode != null) {
            NodeStats stats = nodeTable.getNodeStats(destNode);
            if (stats != null) {
                stats.lastReq = System.currentTimeMillis();
            }
        }
        if (sourceNode != null) {
            NodeStats stats = nodeTable.getNodeStats(sourceNode);
            if (stats != null) {
                if(System.currentTimeMillis() - stats.lastReq < 1000) {
                    responseTime = System.currentTimeMillis() - stats.lastReq;
                    /* clear lastReq */
                    stats.lastReq = 0;
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
                nodeTable.printAck = true;
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
                    System.out.printf("[%s] Sleep Report - no packet received Flag: %02x Dir:%s ",
                            timeStr, flag, (flag & 0x80) > 0 ? "D" : "U");

                } else if ((flag & 0xf) == 0x03) {
                    System.out.printf("[%s] Sleep Report - packet received Flag: %02x Dir:%s HoldTime: %d ",
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
                nodeTable.printAck = true;
                System.out.printf("[%s] *** UDP Message ", timeStr);
                printFromTo(System.out, packet);
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
        } else if (payload instanceof ICMP6Packet) {
            ICMP6Packet icmp6 = (ICMP6Packet) payload;
            if (icmp6.getType() == ICMP6Packet.NEIGHBOR_SOLICITATION) {
                System.out.print("*** Warning - Neighbor solicitation!!! ");
                printFromTo(System.out, packet);
                System.out.println();
                nsPacket++;
            } else if (icmp6.getType() == ICMP6Packet.ECHO_REPLY) {
                if (responseTime < 1000 && responseTime > 0) {
                    System.out.printf("[%s] Echo Reply within: %d", timeStr, responseTime);
                    printFromTo(System.out, packet);
                    System.out.println();
                }
            }
        }
        return true;
    }


    @Override
    public boolean analyzeRawPacket(CapturedPacket packet) {
        // TODO Auto-generated method stub
        /* True => continue */
        return true;
    }
}
