package se.sics.jipv6.core;

import java.util.Formatter;

import se.sics.jipv6.util.Utils;

public class HopByHopOption implements IPv6ExtensionHeader {

    public static final boolean DEBUG = false;

    public static final byte DISPATCH = 0;
    byte nextHeader = 0;
    int len;
    IPPayload next;

    public byte getNextHeader() {
        return nextHeader;
    }

    @Override
    public byte getDispatch() {
        return DISPATCH;
    }

    @Override
    public byte[] generatePacketData(IPv6Packet packet) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void parsePacketData(IPv6Packet packet) {
        /* Assumes that this is the correct position */
        nextHeader = packet.getData(0);
        len = packet.getData(1) * 8 + 8;
        if (DEBUG) {
            System.out.printf("Parsed HBH Option - NH:%d (%02x) len:%d\n",
                    nextHeader & 0xff, nextHeader & 0xff, len);
        }
        packet.incPos(len);
    }

    @Override
    public void printPacket(Formatter out) {
        out.format("HBH Option NH: " + (nextHeader & 0xff) + " (" + Utils.hex8(nextHeader & 0xff) + ")\n");
    }

    public void setNext(IPPayload payload) {
        next = payload;
    }

    @Override
    public IPPayload getNext() {
        return next;
    }

}
