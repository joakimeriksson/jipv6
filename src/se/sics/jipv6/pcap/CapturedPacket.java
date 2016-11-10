package se.sics.jipv6.pcap;

import java.util.Hashtable;

public class CapturedPacket {

    public static final String RSSI = "packet.rssi";
    
    private final long timeMillis;
    private final byte[] payload;
    
    Hashtable<String, Object> attributes = new Hashtable<String, Object>();

    public CapturedPacket(long timeMillis, byte[] payload) {
        this.timeMillis = timeMillis;
        this.payload = payload;
    }

    public void setAttribute(String name, Object value) {
        attributes.put(name, value);
    }
    
    public Object getAttribute(String name) {
        return attributes.get(name);
    }
    
    public long getTimeMillis() {
        return timeMillis;
    }

    public byte[] getPayload() {
        return payload;
    }

    public Hashtable<String, Object> getAttributes() {
        return attributes;
    }

}
