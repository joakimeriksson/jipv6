package se.sics.jipv6.analyzer;

import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.MacPacket;
import se.sics.jipv6.pcap.CapturedPacket;

public interface PacketAnalyzer {
    
    public void init(NodeTable table);

    /* If any analyzer returns false the packet will be "consumed" for the other analyzers */
    public boolean analyzeRawPacket(CapturedPacket packet);
    
    public boolean analyzeMacPacket(MacPacket packet, Node sender, Node receiver);
    
    public boolean analyzeIPPacket(IPv6Packet packet, Node macSender, Node macReceiver);
    
    public void print();
}
