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
 * This file is part of MSPSim.
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

package se.sics.jipv6.mac;

import java.io.PrintStream;

import se.sics.jipv6.core.AbstractPacketHandler;
import se.sics.jipv6.core.MacPacket;
import se.sics.jipv6.util.Utils;

public class IEEE802154Handler extends AbstractPacketHandler {

    public static final boolean DEBUG = false;

    public static final String SOURCE_PAN_ID = "802154.sourcePAN";
    public static final String SOURCE_MODE = "802154.sourceMode";
    public static final String DESTINATION_PAN_ID = "802154.destPAN";
    public static final String DESTINATION_MODE = "802154.destMode";
    public static final String VERSION = "802154.version";
    public static final String ACK_REQ = "802154.ackreq";
    public static final String DATA_PENDING = "802154.dataPending";
    public static final String SECURITY = "802154.security";
    public static final String PACKET_TYPE = "802154.type";
    public static final String PANID_COMPRESSION = "802154.panid_compr";

    public static final String SEQ_NO = "802154.seqno";
    public static final String PAYLOAD_LEN = "802154.len";

    public static final int BEACONFRAME = 0x00;
    public static final int DATAFRAME = 0x01;
    public static final int ACKFRAME = 0x02;
    public static final int CMDFRAME = 0x03;

    public static final String TYPE_NAMES[] = {"BEACON", "DATA", "ACK", "CMD"};


    public static final int SECURITY_BIT = 0x03;
    public static final int PENDING_BIT = 0x04;
    public static final int ACKREQ_BIT = 0x05;
    public static final int PANCOMPR_BIT = 0x06;

    public static final int SHORT_ADDRESS = 2;
    public static final int LONG_ADDRESS = 3;

    private static final byte[] BROADCAST_ADDR = {(byte)0xff, (byte)0xff};

    private int defaultAddressMode = LONG_ADDRESS;
    private byte seqNo = 0;

    private int myPanID = 0xabcd;

    /* create a 802.15.4 packet of the bytes and "dispatch" to the
     * next handler
     */
    public void packetReceived(MacPacket packet) {
        //    IEEE802154Packet newPacket = new IEEE802154Packet(packet);
        /* no dispatch at this level ?! */

        int type = packet.getData(0) & 7;
        int security = (packet.getData(0) >> SECURITY_BIT) & 1;
        int pending = (packet.getData(0) >> PENDING_BIT) & 1;
        int ackRequired = (packet.getData(0) >> ACKREQ_BIT) & 1;
        int panCompression  = (packet.getData(0) >> PANCOMPR_BIT) & 1;
        int seqCompression = packet.getData(1) & 1;
        int destAddrMode = (packet.getData(1) >> 2) & 3;
        int frameVersion = (packet.getData(1) >> 4) & 3;
        int srcAddrMode = (packet.getData(1) >> 6) & 3;

        /* SeqNo can be compressed! */
        int pos = 2;
        int seqNumber = 0;
        if(seqCompression == 0) {
            seqNumber = packet.getData(2);
            pos++;
        } else {
            if(DEBUG) System.out.println("Seqno compressed.");
        }

        packet.setAttribute(DESTINATION_MODE, destAddrMode);
        packet.setAttribute(SOURCE_MODE, srcAddrMode);
        
        int destPanID = 0;
        if (destAddrMode > 0) {
            destPanID = (packet.getData(pos) & 0xff) + ((packet.getData(pos + 1) & 0xff) << 8);
            packet.setAttribute(DESTINATION_PAN_ID, destPanID);
            pos += 2;
            if (destAddrMode == SHORT_ADDRESS) {
                byte[] destAddress = new byte[2];
                destAddress[1] = packet.getData(pos);
                destAddress[0] = packet.getData(pos + 1);
                pos += 2;
                packet.setAttribute(MacPacket.LL_DESTINATION, destAddress);
            } else if (destAddrMode == LONG_ADDRESS) {
                byte[] destAddress = new byte[8];
                for (int i = 0; i < 8; i++) {
                    destAddress[i] = packet.getData(pos + 7 - i);
                }
                pos += 8;
                packet.setAttribute(MacPacket.LL_DESTINATION, destAddress);
            } else {
                // No destination address
            }
        }

        if (srcAddrMode > 0) {
            int srcPanID = 0;
            if (panCompression == 0){
                srcPanID = (packet.getData(pos) & 0xff) + ((packet.getData(pos + 1) & 0xff) << 8);
                pos += 2;
            } else {
                srcPanID = destPanID;
            }
            packet.setAttribute(SOURCE_PAN_ID, srcPanID);
            if (srcAddrMode == SHORT_ADDRESS) {
                byte[] sourceAddress = new byte[2];
                sourceAddress[1] = packet.getData(pos);
                sourceAddress[0] = packet.getData(pos + 1);
                pos += 2;
                packet.setAttribute(MacPacket.LL_SOURCE, sourceAddress);
            } else if (srcAddrMode == LONG_ADDRESS) {
                byte[] sourceAddress = new byte[8];
                for (int i = 0; i < 8; i++) {
                    sourceAddress[i] = packet.getData(pos + 7 - i);
                }
                pos += 8;
                packet.setAttribute(MacPacket.LL_SOURCE, sourceAddress);
            } else {
                // No source address
            }
        }
        packet.incPos(pos);
        packet.setAttribute(PAYLOAD_LEN, packet.getPayloadLength());
        packet.setAttribute(VERSION, frameVersion & 0xff);
        packet.setAttribute(SEQ_NO, seqNumber & 0xff);
        packet.setAttribute(ACK_REQ, ackRequired & 0xff);
        packet.setAttribute(DATA_PENDING, pending & 0xff);
        packet.setAttribute(SECURITY, security & 0xff);
        packet.setAttribute(PACKET_TYPE, type & 0xff);
        packet.setAttribute(PANID_COMPRESSION, panCompression);

        if (DEBUG) {
            System.out.println("802.15.4 Consumed " + pos + " bytes");
            packet.printPacket();
        }
        dispatch(-1, packet);
    }

    /* create a 802.15.4 packet with the given packet as payload, and
     * deliver to the lower layer handler */
    public void sendPacket(MacPacket packet) {
        System.out.println("Packet should be sent!!!");
        byte[] buffer = new byte[127];
        int pos = 0;
        int destPanID = 0xabcd;
        int data = 0;
        /* construct a default packet... needs fixing later */
        /* no security, no compression, etc */
        data = packet.getAttributeAsInt(PACKET_TYPE);
        data = data | (packet.getAttributeAsInt(SECURITY) << SECURITY_BIT);
        data = data | (packet.getAttributeAsInt(ACK_REQ) << ACKREQ_BIT);
        data = data | (packet.getAttributeAsInt(DATA_PENDING) << PENDING_BIT);

        buffer[0] = (byte) data;

        int destMode = defaultAddressMode;
        int srcMode = defaultAddressMode;
        int frameVersion = 0;

        if (Utils.equals(packet.getLinkDestination(), BROADCAST_ADDR)) {
            destMode = SHORT_ADDRESS;
            destPanID = 0xffff;
        }

        buffer[1] = (byte)((destMode << 2) |
                (frameVersion << 4) | (srcMode << 6));
        buffer[2] = seqNo++;

        pos = 3;
        /* Destination PAN */
        buffer[pos++] = (byte) (destPanID & 0xff);
        buffer[pos++] = (byte) (destPanID >> 8);

        byte[] dest = packet.getLinkDestination();
        for (int i = 0; i < dest.length; i++) {
            buffer[pos++] = dest[dest.length - i - 1];
        }

        /* Source PAN */
        buffer[pos++] = (byte) (myPanID & 0xff);
        buffer[pos++] = (byte) (myPanID >> 8);

        byte[] src  = packet.getLinkSource();
        for (int i = 0; i < src.length; i++) {
            buffer[pos++] = src[src.length - i - 1];
        }

        byte[] pHeader = new byte[pos];
        System.arraycopy(buffer, 0, pHeader, 0, pos);
        packet.prependBytes(pHeader);

        lowerLayer.sendPacket(packet);
    }

    public static String getPacketTypeName(int type) {
        if (type >= 0 && type < TYPE_NAMES.length) {
            return TYPE_NAMES[type];
        }
        return "TYPE(" + type + ")";
    }

    public void printPacket(PrintStream out, MacPacket packet) {
        out.print("802.15.4 " + getPacketTypeName(packet.getAttributeAsInt(PACKET_TYPE)) + " from " + Utils.hex16(packet.getAttributeAsInt(SOURCE_PAN_ID)) + "/");
        printAddress(out, packet.getAttributeAsInt(SOURCE_MODE),
                (byte[]) packet.getAttribute(MacPacket.LL_SOURCE));
        out.print(" to " + Utils.hex16(packet.getAttributeAsInt(DESTINATION_PAN_ID)) + "/");
        printAddress(out, packet.getAttributeAsInt(DESTINATION_MODE),
                (byte[]) packet.getAttribute(MacPacket.LL_DESTINATION));
        out.print(" Sec:" + packet.getAttribute(SECURITY));
        out.println(" seqNo: " + packet.getAttributeAsInt(SEQ_NO) + " vers: " +
                packet.getAttributeAsInt(VERSION) + " len: " +
                packet.getAttributeAsInt(PAYLOAD_LEN));
    }

    private void printAddress(PrintStream out, int type, byte[] addr) {
        if (type == SHORT_ADDRESS) {
            out.print(Utils.hex8(addr[0]) + Utils.hex8(addr[1]));
        } else if (type == LONG_ADDRESS) {
            out.print(Utils.hex8(addr[0]) + Utils.hex8(addr[1]) + ":" +
                    Utils.hex8(addr[2]) + Utils.hex8(addr[3]) + ":" +
                    Utils.hex8(addr[4]) + Utils.hex8(addr[5]) + ":" +
                    Utils.hex8(addr[6]) + Utils.hex8(addr[7]));
        }
    }
}
