package se.sics.jipv6.pcap;

public interface CapturedPacket {

    public long getTimeMillis();

    public byte[] getPayload();

}
