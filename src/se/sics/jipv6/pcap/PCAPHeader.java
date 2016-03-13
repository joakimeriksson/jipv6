package se.sics.jipv6.pcap;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class PCAPHeader {

    private static final int PCAP_MAGIC = 0xa1b2c3d4;

    public static final int LINKTYPE_ETHERNET     =   1;
    public static final int LINKTYPE_IEEE802_15_4 = 195;

    private int versionMajor = 2;
    private int versionMinor = 4;
    private int timezone = 0;
    private int timestampAccuracy = 0;
    private int snapshotMaxLength = 4096;
    private int llayerHeaderType = LINKTYPE_IEEE802_15_4;

    public PCAPHeader() {
        //
    }

    public void readHeader(DataInputStream input) throws IOException {
        int magic = input.readInt();
        if (magic != PCAP_MAGIC) {
            throw new IOException("Not a PCAP file");
        }
        this.versionMajor = input.readShort();
        this.versionMinor = input.readShort();
        this.timezone = input.readInt();
        this.timestampAccuracy = input.readInt();
        this.snapshotMaxLength = input.readInt();
        this.llayerHeaderType = input.readInt();
    }

    public void writeHeader(DataOutputStream output) throws IOException {
        output.writeInt(PCAP_MAGIC);
        output.writeShort(this.versionMajor);
        output.writeShort(this.versionMinor);
        output.writeInt(this.timezone);
        output.writeInt(this.timestampAccuracy);
        output.writeInt(this.snapshotMaxLength);
        output.writeInt(this.llayerHeaderType);
    }

    public int getVersionMajor() {
        return versionMajor;
    }

    public void setVersionMajor(int major) {
        this.versionMajor = major;
    }

    public int getVersionMinor() {
        return versionMinor;
    }

    public void setVersionMinor(int minor) {
        this.versionMinor = minor;
    }

    public int getTimezone() {
        return timezone;
    }

    public void setTimezone(int timezone) {
        this.timezone = timezone;
    }

    public int getTimestampAccuracy() {
        return timestampAccuracy;
    }

    public void setTimezoneAccuracy(int timestampAccuracy) {
        this.timestampAccuracy = timestampAccuracy;
    }

    public int getMaxSnapshotLength() {
        return snapshotMaxLength;
    }

    public void setMaxSnapshotLength(int snapshotMaxLength) {
        this.snapshotMaxLength = snapshotMaxLength;
    }

    public int getLinkLayerHeaderType() {
        return llayerHeaderType;
    }

    public void setLinkLayerHeaderType(int llayerHeaderType) {
        this.llayerHeaderType = llayerHeaderType;
    }
}
