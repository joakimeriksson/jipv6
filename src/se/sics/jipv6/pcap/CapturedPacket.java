package se.sics.jipv6.pcap;

public class CapturedPacket {

    private final long timeMillis;
    private final byte[] payload;

    public CapturedPacket(long timeMillis, byte[] payload) {
        this.timeMillis = timeMillis;
        this.payload = payload;
    }

    public long getTimeMillis() {
        return timeMillis;
    }

    public byte[] getPayload() {
        return payload;
    }

}
