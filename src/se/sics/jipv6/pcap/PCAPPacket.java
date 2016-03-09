package se.sics.jipv6.pcap;

public class PCAPPacket implements CapturedPacket {

    private long timestamp;
    private int capturedSize;
    private byte[] payload;

    public PCAPPacket(long timestamp, int capturedSize, byte[] payload) {
        this.timestamp = timestamp;
        this.capturedSize = capturedSize;
        this.payload = payload;
    }

    public long getTimestamp() {
        return this.timestamp;
    }

    @Override
    public long getTimeMillis() {
        return this.timestamp / 1000L;
    }

    public int getCapturedSize() {
        return this.capturedSize;
    }

    public int getPayloadSize() {
        return this.payload.length;
    }

    @Override
    public byte[] getPayload() {
        return this.payload;
    }
}
