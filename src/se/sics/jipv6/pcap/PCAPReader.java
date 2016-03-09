package se.sics.jipv6.pcap;

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;

public class PCAPReader {

    private DataInputStream input;
    private int versionMajor;
    private int versionMinor;
    private int timezone;
    private int timestampAccuracy;
    private int snapshotMaxLength;
    private int llayerHeaderType;
    private boolean isStrippingEthernetHeaders = false;

    public PCAPReader(String filename) throws IOException {
        this.input = new DataInputStream(new FileInputStream(filename));
        int magic = this.input.readInt();
        if (magic != 0xa1b2c3d4) {
            throw new IOException("Not a PCAP file: " + filename);
        }
        this.versionMajor = this.input.readShort();
        this.versionMinor = this.input.readShort();
        this.timezone = this.input.readInt();
        this.timestampAccuracy = this.input.readInt();
        this.snapshotMaxLength = this.input.readInt();
        this.llayerHeaderType = this.input.readInt();
    }

    public boolean isStrippingEthernetHeaders() {
        return isStrippingEthernetHeaders;
    }

    public void setStripEthernetHeaders(boolean stripEthernetHeaders) {
        this.isStrippingEthernetHeaders = stripEthernetHeaders;
    }

    public int getVersionMajor() {
        return versionMajor;
    }

    public int getVersionMinor() {
        return versionMinor;
    }

    public int getTimezone() {
        return timezone;
    }

    public int getTimestampAccuracy() {
        return timestampAccuracy;
    }

    public int getMaxSnapshotLength() {
        return snapshotMaxLength;
    }

    public int getLinkLayerHeaderType() {
        return llayerHeaderType;
    }

    public PCAPPacket readPacket() throws IOException {
        if(this.input.available() == 0) {
            // End of file
            return null;
        }

        long seconds = this.input.readInt() & 0xffffffffL;
        long ms = this.input.readInt() & 0xffffffffL;
        int savedSize = this.input.readInt();
        int capturedSize = this.input.readInt();
        if (isStrippingEthernetHeaders && llayerHeaderType == 0x01) {
            // Skip Ethernet header: 14 bytes
            byte[] hdr = new byte[14];
            this.input.readFully(hdr);
            savedSize = savedSize - 14;
            capturedSize = capturedSize - 14;
        }
        if (savedSize <= 0) {
            throw new IOException("too small segment");
        }
        byte[] data = new byte[savedSize];
        this.input.readFully(data);
        return new PCAPPacket(seconds * 1000000L + ms, capturedSize, data);
    }

    public void close() throws IOException {
        input.close();
    }

}
