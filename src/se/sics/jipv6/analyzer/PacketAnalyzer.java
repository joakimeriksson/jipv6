package se.sics.jipv6.analyzer;

import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.Packet;

public interface PacketAnalyzer {
    
    public void init();
    
    public void analyzePacket(Packet packet);
    
    public void analyzeIPPacket(IPv6Packet packet);
}
