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

    private static final boolean printPayload = true; /* Print UDP payload */

    private int dataPacket;
    private int sleepPacket;
    private int nsPacket;
    private int totPacket;

    private long startTime;

    private PrintStream out;
    
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

    public void init(NodeTable table, PrintStream out) {
        this.nodeTable = table;
        this.out = out;
    }

    public void print() {
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed < 1) {
            elapsed = 1;
        }
        out.printf("Example Analyzer: Tot:%d NS:%d Sleep:%d Data:%d\n",
                totPacket,
                nsPacket, sleepPacket, dataPacket);
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
                    //                    out.println("**** Response within " + (System.currentTimeMillis() - stats.lastReq));
                }
            }
        }

        while (payload instanceof IPv6ExtensionHeader) {
            if (DEBUG) {
                out.print("Analyzer - EXT HDR " + payload.getClass().getSimpleName() + ": ");
                payload.printPacket(out);
            }
            payload = ((IPv6ExtensionHeader) payload).getNext();
        }
        if (payload instanceof UDPPacket) {
            byte[] data = ((UDPPacket) payload).getPayload();

            if (IPv6Packet.isLinkLocal(packet.getDestinationAddress())) {
                nodeTable.printAck = true;
                int flag = data[4] & 0xff;
                int time = (data[6] & 0xff) * 256 + (data[7] & 0xff);
                int seq = (data[5] & 0x0f);
                printStart(out, packet, elapsed);
                if((flag & 0xf) == 0x01) {
                    if (sourceNode != null) {
                        SleepStats sleepInfo = (SleepStats) sourceNode.properties.get("sleepInfo");
                        if (sleepInfo == null) {
                            sourceNode.properties.put("sleepInfo", sleepInfo = new SleepStats());
                        }
                        sleepInfo.sleepSessions++;
                    }
                    out.printf("UDP Sleep Awake in %d: Flag: %02x Dir:%s Seq:%d ",
                            time, flag, (flag & 0x80) > 0 ? "D" : "U", seq);
                } else if ((flag & 0xf) == 0x02) {
                    if (destNode != null) {
                        SleepStats sleepInfo = (SleepStats) destNode.properties.get("sleepInfo");
                        if (sleepInfo != null) {
                            sleepInfo.sleepReports++;
                            sleepInfo.noPacket++;
                        }
                    }
                    out.printf("UDP Sleep Report - no packet recived Flag: %02x Dir:%s Seq:%d ",
                            flag, (flag & 0x80) > 0 ? "D" : "U", seq);

                } else if ((flag & 0xf) == 0x03) {
                    out.printf("UDP Sleep Report - packet recived Flag: %02x Dir:%s Seq: %d HoldTime: %d ",
                            flag, (flag & 0x80) > 0 ? "D" : "U", seq, time);
                    if (destNode != null) {
                        SleepStats sleepInfo = (SleepStats) destNode.properties.get("sleepInfo");
                        if (sleepInfo != null) {
                            sleepInfo.packet++;
                            sleepInfo.lastReportTime = packet.getTimeMillis();
                        }
                    }
                } else {
                    out.println("Unknown sleep packet");
                }
                sleepPacket++;
            } else {
                dataPacket++;
                nodeTable.printAck = true;
                printStart(out, packet, elapsed);
                out.printf("UDP Message (UC/Global) ");
                if (responseTime > 0) {
                    System.out.print(Long.toString(responseTime) + " ");
                }
                if (sourceNode != null) {
                    SleepStats sleepInfo = (SleepStats) sourceNode.properties.get("sleepInfo");
                    if (sleepInfo != null) {
                        long elapsedTime = packet.getTimeMillis() - sleepInfo.lastReportTime;
                        if(elapsedTime < 1000) {
                            out.printf(" Sleepy Node. Time since report: %d avg: %f ",
                                    elapsedTime, sleepInfo.avgReport2ResponseTime);
                            if(sleepInfo.avgReport2ResponseTime == 0) {
                                sleepInfo.avgReport2ResponseTime = elapsedTime;
                            } else {
                                sleepInfo.avgReport2ResponseTime = (sleepInfo.avgReport2ResponseTime * 9.0 +
                                        elapsedTime) / 10.0;
                            }
                        } else {
                            out.printf(" Sleepy Node. Long Time since report: %d avg: %f ",
                                    elapsedTime, sleepInfo.avgReport2ResponseTime);
                        }
                    }
                }
                /* Print the payload of all packets as a String*/
                if (printPayload) {
                    out.print(" ");
                    for (int i = 0; i < data.length; i++) {
                        if(data[i] < ' ') {
                            out.printf(".");
                        } else {
                            out.printf("%c", (char) data[i]);
                        }
                    }
                }
            }
        } else if (payload instanceof ICMP6Packet) {
            ICMP6Packet icmp6 = (ICMP6Packet) payload;
            if (icmp6.getType() == ICMP6Packet.NEIGHBOR_SOLICITATION) {
                printStart(out, packet, elapsed);
                out.print("ICMP6 *** Warning - Neighbor solicitation!!! ");
                out.println();
                nsPacket++;
            } else if (icmp6.getType() == ICMP6Packet.ECHO_REPLY) {
                if (responseTime < 1000 && responseTime > 0) {
                    printStart(out, packet, elapsed);
                    out.printf("ICMP6 Echo Reply within: %d", responseTime);
                    out.println();
                }
            } else if (icmp6.getType() == ICMP6Packet.ECHO_REQUEST) {
                if (responseTime < 1000 && responseTime > 0) {
                    printStart(out, packet, elapsed);
                    out.printf("ICMP6 Echo Request");
                    out.println();
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
