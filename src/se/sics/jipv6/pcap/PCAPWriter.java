package se.sics.jipv6.pcap;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class PCAPWriter {

    private final DataOutputStream output;
    private final int maxSnapshotSize;
    private CCITT_CRC packetCrc = new CCITT_CRC();
    private boolean isAddingCRC = false;

    public PCAPWriter(String filename) throws IOException {
        this(filename, null);
    }

    public PCAPWriter(String filename, PCAPHeader header) throws IOException {
        this.output = new DataOutputStream(new BufferedOutputStream(new FileOutputStream(filename)));
        if (header == null) {
            header = new PCAPHeader();
            header.setMaxSnapshotLength(4096);
        }

        // Only 802.15.4 frames support by this exporter
        header.setLinkLayerHeaderType(PCAPHeader.LINKTYPE_IEEE802_15_4);
        header.writeHeader(this.output);

        this.maxSnapshotSize = header.getMaxSnapshotLength();
    }

    public boolean isAddingCRC() {
        return isAddingCRC;
    }

    public void setAddingCRC(boolean isAddingCRC) {
        this.isAddingCRC = isAddingCRC;
    }

    public void writePacket(long timeMillis, byte[] data) throws IOException {
        int size = data.length;
        int padding = this.isAddingCRC ? 2 : 0;
        if (size + padding > this.maxSnapshotSize) {
            size = this.maxSnapshotSize - padding;
        }
        output.writeInt((int) (timeMillis / 1000));
        output.writeInt((int) (timeMillis % 1000) * 1000);
        // Saved size
        output.writeInt(size + padding);
        // Captured size
        output.writeInt(data.length + padding);
        /* and the data */
        output.write(data, 0, size);
        if (this.isAddingCRC) {
            packetCrc.reset();
            packetCrc.addBitrev(data, 0, size);
            output.writeShort(packetCrc.getCRCBitrev());
        }
        output.flush();
    }

    public void writePacket(CapturedPacket captured) throws IOException {
        this.writePacket(captured.getTimeMillis(), captured.getPayload());
    }

    public void flush() throws IOException {
        output.flush();
    }

    public void close() throws IOException {
        output.close();
    }
}
