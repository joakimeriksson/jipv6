package se.sics.jipv6.analyzer;

import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.Packet;

public interface PacketAnalyzer {
    
    public void init(NodeTable table);
    
    public void analyzePacket(Packet packet, Node sender, Node receiver);
    
    public void analyzeIPPacket(IPv6Packet packet);
}
