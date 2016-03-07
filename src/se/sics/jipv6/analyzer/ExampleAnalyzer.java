package se.sics.jipv6.analyzer;

import se.sics.jipv6.core.ICMP6Packet;
import se.sics.jipv6.core.IPPayload;
import se.sics.jipv6.core.IPv6ExtensionHeader;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.Packet;
import se.sics.jipv6.core.RPLPacket;
import se.sics.jipv6.core.UDPPacket;

public class ExampleAnalyzer implements PacketAnalyzer {

    public void init() {
        
    }
    
    /* MAC packet received */
    public void analyzePacket(Packet packet) {
        
    }
    
    /* IPv6 packet received */
    public void analyzeIPPacket(IPv6Packet packet) {
        IPPayload payload = packet.getIPPayload();
        while (payload instanceof IPv6ExtensionHeader) {
            System.out.println("Analyzer - EXT HDR:");
            payload.printPacket(System.out);
            payload = ((IPv6ExtensionHeader) payload).getNext();
        }
        if (payload instanceof UDPPacket) {
            System.out.println("Analyzer - UDP Packet");
            if (IPv6Packet.isLinkLocal(packet.getDestinationAddress())) {
                System.out.print("*** Link Local Message: Possibly Sleep from:");
                IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                System.out.println();
            } else {
                System.out.println("*** Message to/from Fiona");
            }
        } else if (payload instanceof RPLPacket) {
            RPLPacket rpl = (RPLPacket) payload;
            switch (rpl.getCode()) {
            case RPLPacket.RPL_DIS:
                if (IPv6Packet.isLinkLocal(packet.getDestinationAddress())) {
                    /* ... */
                    System.out.print("*** Probe or repair from ");
                    IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                    System.out.println();
                } else {
                    System.out.print("*** Warning - broadcast DIS!!! from");
                    IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                    System.out.println();
                }
                break;
            case RPLPacket.RPL_DIO:
                break;
            }
        } else if (payload instanceof ICMP6Packet) {
            ICMP6Packet icmp6 = (ICMP6Packet) payload;
            if (icmp6.getType() == ICMP6Packet.NEIGHBOR_SOLICITATION) {
                System.out.print("*** Warning - Neighbor solicitation!!! from: ");
                IPv6Packet.printAddress(System.out, packet.getSourceAddress());
                System.out.println();
            } else {
            }
        }
    }
}
