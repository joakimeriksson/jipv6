package se.sics.jipv6.pcap;

public class PCAPPacket extends CapturedPacket {

    private long timestamp;
    private int capturedSize;

    public PCAPPacket(long timestamp, int capturedSize, byte[] payload) {
        super(timestamp / 1000L, payload);
        this.timestamp = timestamp;
        this.capturedSize = capturedSize;
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    public int getCapturedSize() {
        return this.capturedSize;
    }

}
