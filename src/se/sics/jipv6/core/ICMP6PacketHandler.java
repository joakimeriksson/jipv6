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
import se.sics.jipv6.util.Utils;

public class ICMP6PacketHandler {

    public static final boolean DEBUG = false;

    IPStack ipStack;
    private ICMP6Listener listener = null;

    public ICMP6PacketHandler(IPStack stack) {
        ipStack = stack;
    }

    public void setICMP6Listener(ICMP6Listener l) {
        listener = l;
    }

    public void handlePacket(IPv6Packet packet) {
        ICMP6Packet icmpPacket = new ICMP6Packet();
        icmpPacket.parsePacketData(packet);
        packet.setIPPayload(icmpPacket);

        if (DEBUG) icmpPacket.printPacket(System.out);

        if (listener != null) {
            if (listener.ICMP6PacketReceived(packet))
                return;
        }

        /* handle packet - just a test for now */
        ICMP6Packet p;
        IPv6Packet ipp;
        switch (icmpPacket.type) {
        case ICMP6Packet.ECHO_REQUEST:
            p = new ICMP6Packet();
            p.type = ICMP6Packet.ECHO_REPLY;
            p.seqNo = icmpPacket.seqNo;
            p.id = icmpPacket.id;
            p.echoData = icmpPacket.echoData;
            ipp = new IPv6Packet();
            ipp.setIPPayload(p);
            // is this ok?
            ipp.destAddress = packet.sourceAddress;
            ipp.sourceAddress = ipStack.myIPAddress;

            ipStack.sendPacket(ipp, packet.netInterface);
            break;
        case ICMP6Packet.ECHO_REPLY:
            if (DEBUG) System.out.println("ICMP6 got echo reply!!");
            break;
            /* this should be handled by the neighbor manager */
        case ICMP6Packet.NEIGHBOR_SOLICITATION:
            p = new ICMP6Packet();
            p.targetAddress = icmpPacket.targetAddress;
            p.type = ICMP6Packet.NEIGHBOR_ADVERTISEMENT;
            p.flags = ICMP6Packet.FLAG_SOLICITED |
                    ICMP6Packet.FLAG_OVERRIDE;
            if (ipStack.isRouter()) {
                p.flags |= ICMP6Packet.FLAG_ROUTER;
            }
            /* always send the linkaddr option */
            p.addLinkOption(ICMP6Packet.TARGET_LINKADDR, ipStack.getLinkLayerAddress());
            ipp = new IPv6Packet();
            ipp.setIPPayload(p);
            // is this ok?
            if (Utils.equals(packet.sourceAddress, IPStack.UNSPECIFIED)) {
                ipp.destAddress = IPStack.ALL_NODES;
            } else {
                ipp.destAddress = packet.sourceAddress;
            }

            /* always link lokal address here ??? - TODO: on which link?!*/
            ipp.sourceAddress = ipStack.myLocalIPAddress;
            ipStack.sendPacket(ipp, packet.netInterface);
            break;
        case ICMP6Packet.ROUTER_SOLICITATION:
            ipStack.getNeighborManager().receiveNDMessage(packet);
            break;
        case ICMP6Packet.ROUTER_ADVERTISEMENT:
            if (!ipStack.isRouter()) {
                byte[] prefixInfo = icmpPacket.getOption(ICMP6Packet.PREFIX_INFO);
                if (prefixInfo != null) {
                    byte[] prefix = new byte[16];
                    System.arraycopy(prefixInfo, 16, prefix, 0, prefix.length);
                    int size = prefixInfo[2];
                    ipStack.setPrefix(prefix, size);

                    ipStack.getNeighborManager().receiveNDMessage(packet);
                }
            }
            break;
        }
    }
}
