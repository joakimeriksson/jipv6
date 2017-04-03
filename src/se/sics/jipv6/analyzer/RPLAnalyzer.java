package se.sics.jipv6.analyzer;

import java.util.Formatter;

import se.sics.jipv6.core.IPPayload;
import se.sics.jipv6.core.IPv6ExtensionHeader;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.MacPacket;
import se.sics.jipv6.core.RPLPacket;
import se.sics.jipv6.pcap.CapturedPacket;

public class RPLAnalyzer implements PacketAnalyzer {

    static class RPLStats {

        int ucDIS;
        int mcDIS;
        int ucDIO;
        int mcDIO;
        int DAO;
        int DAO_ACK;
        int rplRank;
        int topologyNodeID; /* for the topology generator */
        byte[] parentAddr = null;

        public String toString() {
            String parentStr = "-";
            if (parentAddr != null) {
                parentStr = IPv6Packet.addressToString(parentAddr);
            }
            return "RPL Sent: ucDIO:" + ucDIO + " mcDIO:" + mcDIO + " ucDIS:" + ucDIO + " mcDIS:" + mcDIS +
                    " DAO:" + DAO + " DAO_ACK:" + DAO_ACK + " Rank:" + (rplRank / 128.0) + " Parent: " + parentStr;
        }
    }

    private int dioPacket;
    private int bcDISPacket;
    private int ucDISPacket;
    private int daoPacket;


    private NodeTable nodeTable;
    private Formatter out;

    @Override
    public void init(NodeTable table, Formatter out) {
        this.nodeTable = table;
        this.out = out;
    }

    @Override
    public boolean analyzeRawPacket(CapturedPacket packet) {
        // TODO Auto-generated method stub
        return true;
    }

    @Override
    public boolean analyzeMacPacket(MacPacket packet, Node sender,
            Node receiver) {
        // TODO Auto-generated method stub
        return true;
    }

    @Override
    public boolean analyzeIPPacket(IPv6Packet packet, Node macSender,
            Node macReceiver) {
        IPPayload payload = packet.getIPPayload();
        Node sourceNode = nodeTable.getNodeByIP(packet.getSourceAddress());
        RPLStats stats = null;
        if (sourceNode != null) {
            stats = (RPLStats) sourceNode.properties.get("rplstats");
            if (stats == null) {
                stats = new RPLStats();
                sourceNode.properties.put("rplstats", stats);
            }
        }

        long elapsed = nodeTable.getElapsed(packet);
        while (payload instanceof IPv6ExtensionHeader) {
            payload = ((IPv6ExtensionHeader) payload).getNext();
        }

        if (payload instanceof RPLPacket) {
            RPLPacket rpl = (RPLPacket) payload;
            printStart(out, packet, elapsed);
            packet.setAttribute("color", "green");
            switch (rpl.getCode()) {
            case RPLPacket.RPL_DIS:
                if (IPv6Packet.isLinkLocal(packet.getDestinationAddress())) {
                    /* ... */
                    nodeTable.printAck = true;
                    out.format("DIS - *** Probe or repair ");
                    ucDISPacket++;
                    if (stats != null) {
                        stats.ucDIS++;
                    }
                } else {
                    out.format("DIS - *** Warning - broadcast DIS!!!\n");
                    bcDISPacket++;
                    if (stats != null) {
                        stats.mcDIS++;
                    }
                }
                packet.setAttribute("ip.type", "RPL-DIS");
                break;
            case RPLPacket.RPL_DIO:
                dioPacket++;
                String mCast = IPv6Packet.isLinkLocal(packet.getDestinationAddress()) ? "UC" : "MC";
                out.format("DIO (" + mCast + ") ");
                rpl.printPacket(out);
                if (stats != null) {
                    if ("UC".equals(mCast)) {
                        stats.ucDIO++;
                        stats.rplRank = rpl.rank;
                    } else {
                        stats.mcDIO++;
                        stats.rplRank = rpl.rank;
                    }
                }
                packet.setAttribute("ip.type", "RPL-DIO");
                break;
            case RPLPacket.RPL_DAO:
                daoPacket++;
                nodeTable.printAck = true;
                out.format("DAO ");
                rpl.printPacket(out);
                if (stats != null) {
                    stats.DAO++;
                    stats.parentAddr = packet.getDestinationAddress();
                }
                packet.setAttribute("ip.type", "RPL-DAO");
                break;
            case RPLPacket.RPL_DAO_ACK:
                nodeTable.printAck = true;
                out.format("DAO ACK");
                if (stats != null) {
                    stats.DAO_ACK++;
                }
                packet.setAttribute("ip.type", "RPL-DAO_ACK");
                break;
            }
        }
        return true;
    }

    @Override
    public void print() {
        out.format("RPL mcDIS: " + bcDISPacket + " ucDIS: " + ucDISPacket + " DIO: " + dioPacket + " DAO: " + daoPacket + "\n");
    }
    
    public static String getRPLTopology(NodeTable nodeTable) {
        Node[] nodes = nodeTable.getAllNodes();
        int nodeId = 1;
        StringBuilder sb = new StringBuilder();
        sb.append("var nodes = [");
        /* Note - if this is called multiple times - the topology view might be broken... */
        for (Node node : nodes) {
            RPLStats stats = (RPLStats) node.properties.get("rplstats");
            if (stats != null) {
                stats.topologyNodeID = nodeId;
                if(nodeId > 1) {
                    sb.append(',');
                }
                sb.append("{id:").append(nodeId).append(", label:'N").append(nodeId).append("'}\n");
                nodeId++;
                /* Id to Node map */
            }
        }
        sb.append("];\n");
        sb.append("var edges = [");
        int edge = 0;
        for (Node node : nodes) {
            RPLStats stats = (RPLStats) node.properties.get("rplstats");
            if (stats != null) {
                if (stats.parentAddr != null) {
                    Node parent = nodeTable.getNodeByIP(stats.parentAddr);
                    RPLStats pStats = (RPLStats) parent.properties.get("rplstats");
                    if (pStats != null) {
                        if (edge > 0) sb.append(',');
                        edge++;
                        sb.append("{from:").append(stats.topologyNodeID).append(",to:").
                            append(pStats.topologyNodeID).append("}\n");
                    }
                }
            }
        }
        sb.append("];");
        return sb.toString();
    }

}
