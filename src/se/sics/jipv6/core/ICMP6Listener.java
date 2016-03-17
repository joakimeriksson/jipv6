package se.sics.jipv6.core;

public interface ICMP6Listener {
    /* ICMPv6 Packet received */
    public boolean ICMP6PacketReceived(IPv6Packet packet);
}
