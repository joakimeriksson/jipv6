package se.sics.jipv6.analyzer;

import java.util.Formatter;

import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.MacPacket;
import se.sics.jipv6.pcap.CapturedPacket;

public interface PacketAnalyzer {

    public void init(NodeTable table, Formatter out);

    /* If any analyzer returns false the packet will be "consumed" for the other analyzers */
    public boolean analyzeRawPacket(CapturedPacket packet);

    public boolean analyzeMacPacket(MacPacket packet, Node sender, Node receiver);

    public boolean analyzeIPPacket(IPv6Packet packet, Node macSender, Node macReceiver);

    public void print();
    
    default public void printFromTo(Formatter out, IPv6Packet packet) {
        out.format("from ");
        IPv6Packet.printAddress(out, packet.getSourceAddress());
        out.format(" to ");
        IPv6Packet.printAddress(out, packet.getDestinationAddress());
    }

    default public void printStart(Formatter out, MacPacket packet, long elapsed) {
        out.format("[%d:%02d:%02d.%03d %3d] ", elapsed / (1000 * 3600) , elapsed / (1000 * 60) % 60,
                (elapsed / 1000) % 60, elapsed % 1000, packet.getTotalLength());
    }

    default public void printStart(Formatter out, IPv6Packet packet, long elapsed) {
        String timeStr = String.format("[%d:%02d:%02d.%03d %3d] %3d", elapsed / (1000 * 3600) , elapsed / (1000 * 60) % 60,
                (elapsed / 1000) % 60, elapsed % 1000, packet.getTotalLength(), packet.getAttribute(CapturedPacket.RSSI));
        out.format(timeStr);
        out.format(" ");
        IPv6Packet.printAddress(out, packet.getSourceAddress());
        out.format("%c", packet.isSourceMACBased() ? '*' : '-');
        out.format(" -> ");
        IPv6Packet.printAddress(out, packet.getDestinationAddress());
        out.format("%c", packet.isDestinationMACBased() ? '*' : '-');
        out.format(" ");
    }

    
}
