package se.sics.jipv6.analyzer;

import java.io.PrintStream;

import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.MacPacket;
import se.sics.jipv6.pcap.CapturedPacket;

public interface PacketAnalyzer {

    public void init(NodeTable table, PrintStream out);

    /* If any analyzer returns false the packet will be "consumed" for the other analyzers */
    public boolean analyzeRawPacket(CapturedPacket packet);

    public boolean analyzeMacPacket(MacPacket packet, Node sender, Node receiver);

    public boolean analyzeIPPacket(IPv6Packet packet, Node macSender, Node macReceiver);

    public void print();
    
    default public void printFromTo(PrintStream out, IPv6Packet packet) {
        out.print("from ");
        IPv6Packet.printAddress(out, packet.getSourceAddress());
        out.print(" to ");
        IPv6Packet.printAddress(out, packet.getDestinationAddress());
    }

    default public void printStart(PrintStream out, MacPacket packet, long elapsed) {
        String timeStr = String.format("[%d:%02d:%02d.%03d %3d]", elapsed / (1000 * 3600) , elapsed / (1000 * 60) % 60,
                (elapsed / 1000) % 60, elapsed % 1000, packet.getTotalLength());
        out.print(timeStr);
        out.print(" ");
    }

    default public void printStart(PrintStream out, IPv6Packet packet, long elapsed) {
        String timeStr = String.format("[%d:%02d:%02d.%03d %3d]", elapsed / (1000 * 3600) , elapsed / (1000 * 60) % 60,
                (elapsed / 1000) % 60, elapsed % 1000, packet.getTotalLength());
        out.print(timeStr);
        out.print(" ");
        IPv6Packet.printAddress(out, packet.getSourceAddress());
        out.printf("%c", packet.isSourceMACBased() ? '*' : '-');
        out.print(" -> ");
        IPv6Packet.printAddress(out, packet.getDestinationAddress());
        out.printf("%c", packet.isDestinationMACBased() ? '*' : '-');
        out.print(" ");
    }

    
}
