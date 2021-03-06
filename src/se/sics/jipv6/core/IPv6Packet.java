/**
 * Copyright (c) 2009, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of jipv6.
 *
 * $Id: $
 *
 * -----------------------------------------------------------------
 *
 *
 * Author  : Joakim Eriksson
 * Created :  mar 2009
 * Updated : $Date:$
 *           $Revision:$
 */

package se.sics.jipv6.core;
import java.util.Formatter;

import se.sics.jipv6.util.Utils;

/**
 * @author Joakim Eriksson, SICS
 *
 */
public class IPv6Packet extends MacPacket implements IPPacketer {

    public static final int ICMP6_DISPATCH = 58;
    public static final boolean DEBUG = false; // true;

    int version;
    int trafficClass;
    int flowLabel;
    byte nextHeader;
    int hopLimit;
    byte[] sourceAddress = new byte[16];
    byte[] destAddress = new byte[16];

    int ipLen = 0;
    int payloadLen = 0;
    IPPayload ipPayload;
    public NetworkInterface netInterface;


    public IPv6Packet() {
        this(System.currentTimeMillis());
    }

    public IPv6Packet(long time) {
        super(time);
        version = 6;
        flowLabel = 0;
        hopLimit = 255;
    }

    public IPv6Packet(MacPacket packet) {
        this(packet.getTimeMillis());
        // copy over all the data from the packet...
        // is this the right way to do this???
        this.currentPos = packet.currentPos;
        this.attributes = packet.attributes;
        this.packetData = packet.packetData;
        ipLen = packetData.length - currentPos;
    }

    public IPv6Packet(IPPayload pl) {
        this();
        nextHeader = pl.getDispatch();
        ipPayload = pl;
    }

    public IPv6Packet(IPPayload pl, byte[] source, byte[] dest) {
        this(pl);
        this.sourceAddress = source;
        this.destAddress = dest;
    }

    public static boolean isLinkLocal(byte[] destinationAddress) {
        return destinationAddress[0] == (byte) 0xfe && destinationAddress[1] == (byte) 0x80;
    }

    public static boolean isEqual(byte[] a1, byte[] a2) {
        if (a1 != null && a2 != null) {
            if (a1.length != a2.length) return false;
            for(int i = 0; i < a1.length; i++) {
                if (a1[i] != a2[i]) return false;
            }
            return true;
        }
        /* null == null ? */
        return false;
    }

    public int getTrafficClass() {
        return trafficClass;
    }

    public void setTrafficClass(int trafficClass) {
        this.trafficClass = trafficClass;
    }

    public int getFlowLabel() {
        return flowLabel;
    }

    public void setFlowLabel(int flowLabel) {
        this.flowLabel = flowLabel;
    }

    public byte getNextHeader() {
        return nextHeader;
    }

    public void setNextHeader(byte nextHeader) {
        this.nextHeader = nextHeader;
    }

    public int getHopLimit() {
        return hopLimit;
    }

    public void setHopLimit(int hopLimit) {
        this.hopLimit = hopLimit;
    }


    public IPv6Packet replyPacket(IPPayload payload) {
        IPv6Packet ipPacket = new IPv6Packet();
        ipPacket.destAddress = sourceAddress;
        ipPacket.ipPayload = payload;
        ipPacket.nextHeader = payload.getDispatch();
        return ipPacket;
    }

    public byte[] getSourceAddress() {
        return sourceAddress;
    }

    public void setSourceAddress(byte[] addr) {
        sourceAddress = addr;
    }

    public byte[] getDestinationAddress() {
        return destAddress;
    }

    public void setDestinationAddress(byte[] addr) {
        destAddress = addr;
    }

    public void printPacket(Formatter out) {
        out.format("IPv6: from ");
        printAddress(out, sourceAddress);
        out.format(" to ");
        printAddress(out, destAddress);
        out.format(" NxHdr: " + nextHeader + "\n");
    }

    public static String addressToString(byte[] address) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < 16; i+=2) {
            if (i > 0) {
                str.append(":");
            }
            str.append(Utils.hex16((((address[i] & 0xff) << 8) | (address[i + 1] & 0xff))));
        }
        return str.toString();
    }

    public static void printAddress(Formatter out, byte[] address) {
        for (int i = 0; i < 16; i+=2) {
            out.format(Utils.hex16((((address[i] & 0xff) << 8) | (address[i + 1] & 0xff))));
            if (i < 14) {
                out.format(":");
            }
        }
    }

    /* this is for setting raw packet data */
    //TODO: should not take an argument here??? it should parse its own
    // data array???
    public boolean parsePacketData(IPv6Packet packet) {
        version = (packet.getData(0) & 0xff) >> 4;
            if (DEBUG) {
                System.out.println("IPv6Packet: version: " + version);
            }
            if (version != 6) {
                return false;
            }
            trafficClass = ((packet.getData(0) & 0x0f) << 4)
                    + ((packet.getData(1) & 0xff) >> 4);
            flowLabel = ((packet.getData(1) & 0x0f) << 16)
                    + ((packet.getData(2) & 0xff) << 8)
                    + (packet.getData(3) & 0xff);
            payloadLen = ((packet.getData(4) & 0xff) << 8) + (packet.getData(5) & 0xff);
            nextHeader = packet.getData(6);
            hopLimit = packet.getData(7) & 0xff;
            packet.copy(8, sourceAddress, 0, 16);
            packet.copy(24, destAddress, 0, 16);
            // move position 40 bytes forward for handling next headers / payload
            packet.incPos(40);
            return true;
    }

    public static void set32(byte[] data, int pos, long value) {
        data[pos++] = (byte) ((value >> 24) & 0xff);
        data[pos++] = (byte) ((value >> 16) & 0xff);
        data[pos++] = (byte) ((value >> 8) & 0xff);
        data[pos++] = (byte) (value & 0xff);
    }

    public static long getLong(byte[] data, int pos) {
        long lval = (data[pos] & 0xff) + ((data[pos + 1] & 0xffL) << 8) +
                ((data[pos + 2] & 0xffL) << 16) + ((data[pos + 3] & 0xffL) << 24) +
                ((data[pos + 4] & 0xffL) << 32) + ((data[pos + 5] & 0xffL)<< 40) +
                ((data[pos + 6] & 0xffL) << 48) + ((data[pos + 7] & 0xffL) << 56);
        return lval;
    }

    /* not yet working checksum code... */
    public int upperLayerHeaderChecksum(byte nextHeader) {
        /* First sum pseudoheader. */
        /* IP protocol and length fields. This addition cannot carry. */
        if (payloadLen == 0) throw new IllegalStateException("No payload length when calculating upper layer checksum.");
        int sum = payloadLen + (nextHeader & 0xff);
        /* Sum IP source and destination addresses. */
        sum = checkSum(sum, sourceAddress, 16);
        sum = checkSum(sum, destAddress, 16);

        /* Sum upper layer header and data is done separately.... */
        /* -- needs to get hold of uncompressed payload for that ... */

        return sum;
    }

    public static int checkSum(int sum, byte[] data, int size) {
        for (int i = 0; i < size - 1; i+= 2) {
            int dsum = ((data[i] & 0xff) << 8) | (data[i + 1] & 0xff);
            sum = (sum + dsum) & 0xffff;
            if (sum < dsum) sum++;
        }
        /* final byte - if any*/
        if ((size & 1) > 0) {
            int dsum = ((data[size - 1] & 0xff) << 8);
            sum = (sum + dsum) & 0xffff;
            if (sum < dsum) sum++;
        }
        return sum;
    }

    public static boolean isMACBased(byte[] address, byte[] macAddress) {
        if(address == null || macAddress == null) return false;

        if (address[8] == (macAddress[0] ^ 0x02)) {
            for (int i = 1; i < macAddress.length; i++) {
                if (address[8 + i] != macAddress[i])
                    return false;
            }
            return true;
        }
        return false;
    }

    public boolean isSourceMACBased() {
        byte[] macAddress = getLinkSource();
        return isMACBased(sourceAddress, macAddress);
    }

    public boolean isMulticastDestination() {
        return (destAddress[0] == (byte)0xff);
    }

    /* how can we check this before we know the MAC address??? */
    public boolean isDestinationMACBased() {
        byte[] macAddress = getLinkDestination();
        return isMACBased(destAddress, macAddress);
    }

    public byte getDispatch() {
        return nextHeader;
    }

    public void copyHeader(byte[] dataPacket, int length) {
        dataPacket[0] = (byte) (0x60 | (trafficClass >> 4) & 0x0f);
        dataPacket[1] = (byte) (((trafficClass & 0xf) << 4) |
                ((flowLabel >> 16) & 0xf));
        dataPacket[2] = (byte) ((trafficClass >> 8) & 0xff);
        dataPacket[3] = (byte) (trafficClass & 0xff);

        dataPacket[4] = (byte) ((length >> 8) & 0xff);
        dataPacket[5] = (byte) (length & 0xff);

        dataPacket[6] = (byte) (nextHeader & 0xff);
        dataPacket[7] = (byte) (hopLimit & 0xff);

        int pos = 8;
        System.arraycopy(getSourceAddress(), 0, dataPacket, pos, 16);
        pos += 16;
        System.arraycopy(getDestinationAddress(), 0, dataPacket, pos, 16);
        pos += 16;
    }
    // TODO: should not take an argument here - should be this packet
    // that should be generating the data???
    public byte[] generatePacketData(IPv6Packet packet) {
        byte[] payload = ipPayload.generatePacketData(packet);
        int size = 40 + payload.length;
        byte[] dataPacket = new byte[size];
        copyHeader(dataPacket, payload.length);

        System.arraycopy(payload, 0, dataPacket, 40, payload.length);
        return dataPacket;
    }

    public IPPayload getIPPayload() {
        return ipPayload;
    }

    public void setIPPayload(IPPayload ipp) {
        ipPayload = ipp;
        nextHeader = ipp.getDispatch();
    }

    public static void printMACAddress(Formatter out, byte[] data,
            int pos, int size) {
        for (int i = 0; i < size; i++) {
            out.format(Utils.hex8(data[i + pos]));
            if (i < size - 1)
                out.format(":");
        }
    }

    /* parse a hex x:y:z... address */
    public static byte[] parseAddress(String addressStr) {
        byte[] address = new byte[16];
        int hexVal = 0;
        int pos = 0;
        int splitPos = 0;
        addressStr = addressStr.toLowerCase();
        for (int i = 0; i < addressStr.length() && pos < 16; i++) {
            char c = addressStr.charAt(i);
            if (c == ':') {
                address[pos++] = (byte)(hexVal >> 8);
                address[pos++] = (byte)(hexVal & 0xff);
                if (i + 1 < addressStr.length() &&
                        addressStr.charAt(i + 1) == ':') {
                    splitPos = pos;
                }
                hexVal = 0;
            } else if (c >= '0' && c <= '9') {
                hexVal = (hexVal << 4) + c - '0';
            } else if (c >= 'a' && c <= 'f') {
                hexVal = (hexVal << 4) + c - 'a' + 10;
            }
        }
        if (splitPos != 0) {
            // we should move some bytes forward...
        }

        return address;
    }

    public boolean isSourceUnspecified() {
        for (int i = 0; i < sourceAddress.length; i++) {
            if (sourceAddress[i] != 0) return false;
        }
        return true;
    }

    public static void main(String[] args) {
        String iphex = "6000000000200001fe80000000000000023048fffe904cd2ff02000000000000000000026c5b5f303a000100050200008300527800000000ff02000000000000000000026c5b5f30";
        if(args.length > 0) {
            iphex = args[0];
            System.out.println("Parsing: '" + args[0] + "'");
        }
        byte[] data = Utils.hexconv(iphex);
        IPv6Packet packet = new IPv6Packet();
        packet.setBytes(data);
        packet.parsePacketData(packet);
        packet.printPacket(new Formatter(System.out));
        
        if (packet.nextHeader == 58) {
            ICMP6Packet icmpPacket = new ICMP6Packet();
            icmpPacket.parsePacketData(packet);
            icmpPacket.printPacket(new Formatter(System.out));
        }
    }
}
