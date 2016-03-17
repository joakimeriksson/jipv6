package se.sics.jipv6.analyzer;

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

    @Override
    public void init(NodeTable table) {
        nodeTable = table;
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

        long elapsed = nodeTable.getElapsed();
        String timeStr = String.format("%d:%02d:%02d.%03d %3d", elapsed / (1000 * 3600) , elapsed / (1000 * 60) % 60,
                (elapsed / 1000) % 60, elapsed % 1000, packet.getTotalLength());

        while (payload instanceof IPv6ExtensionHeader) {
            payload = ((IPv6ExtensionHeader) payload).getNext();
        }

        if (payload instanceof RPLPacket) {
            RPLPacket rpl = (RPLPacket) payload;
            switch (rpl.getCode()) {
            case RPLPacket.RPL_DIS:
                if (IPv6Packet.isLinkLocal(packet.getDestinationAddress())) {
                    /* ... */
                    nodeTable.printAck = true;
                    System.out.printf("[%s] *** Probe or repair from: ", timeStr);
                    IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                    System.out.print(" ");
                    ucDISPacket++;
                    if (stats != null) {
                        stats.ucDIS++;
                    }
                } else {
                    System.out.printf("[%s] *** Warning - broadcast DIS!!! from: ", timeStr);
                    IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                    System.out.println();
                    bcDISPacket++;
                    if (stats != null) {
                        stats.mcDIS++;
                    }
                }
                break;
            case RPLPacket.RPL_DIO:
                dioPacket++;
                String mCast = IPv6Packet.isLinkLocal(packet.getDestinationAddress()) ? "UC" : "MC";
                System.out.printf("[%s] DIO (" + mCast + ") from: ", timeStr);
                IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                System.out.print(" ");
                rpl.printPacket(System.out);
                if (stats != null) {
                    if ("UC".equals(mCast)) {
                        stats.ucDIO++;
                        stats.rplRank = rpl.rank;
                    } else {
                        stats.mcDIO++;
                        stats.rplRank = rpl.rank;
                    }
                }
                break;
            case RPLPacket.RPL_DAO:
                daoPacket++;
                nodeTable.printAck = true;
                System.out.printf("[%s] DAO from: ", timeStr);
                IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                System.out.print(" ");
                rpl.printPacket(System.out);
                if (stats != null) {
                    stats.DAO++;
                    stats.parentAddr = packet.getDestinationAddress();
                }
                break;
            case RPLPacket.RPL_DAO_ACK:
                nodeTable.printAck = true;
                System.out.printf("[%s] DAO ACK from: ", timeStr);
                IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                if (stats != null) {
                    stats.DAO_ACK++;
                }
                break;
            }
        }
        return true;
    }

    @Override
    public void print() {
        System.out.println("RPL mcDIS: " + bcDISPacket + " ucDIS: " + ucDISPacket + " DIO: " + dioPacket + " DAO: " + daoPacket);
    }

}
