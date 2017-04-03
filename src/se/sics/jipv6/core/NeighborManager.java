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
import java.util.TimerTask;
public class NeighborManager extends TimerTask {

    private NeighborTable neigborTable;
    private IPStack ipStack;
    private long nextRS = 0;
    private long nextRA = 0;
    private boolean duplicateDetectionNS;

    public NeighborManager(IPStack stack, NeighborTable table) {
        neigborTable = table;
        ipStack = stack;
        stack.getTimer().schedule(this, 1000, 1000);
    }

    public void run() {
        long time = System.currentTimeMillis();
        if (!duplicateDetectionNS) {
            /* send a duplicate detection message */
            System.out.println("NeighborManager: sending neighbor solicitation (DAD)");
            duplicateDetectionNS = true;
            ICMP6Packet icmp = new ICMP6Packet(ICMP6Packet.NEIGHBOR_SOLICITATION);
            icmp.targetAddress = ipStack.myLinkAddress;
            IPv6Packet ipp = new IPv6Packet(icmp, ipStack.myLocalIPAddress, ipStack.myLocalSolicited);
            ipStack.sendPacket(ipp, null);
        } else if (!ipStack.isRouter() && neigborTable.getDefrouter() == null && nextRS < time) {
            System.out.println("NeighborManager: sending router solicitation");
            nextRS = time + 10000;
            ICMP6Packet icmp = new ICMP6Packet(ICMP6Packet.ROUTER_SOLICITATION);
            icmp.addLinkOption(ICMP6Packet.SOURCE_LINKADDR,
                    ipStack.getLinkLayerAddress());
            IPv6Packet ipp = new IPv6Packet(icmp, ipStack.myLocalIPAddress, IPStack.ALL_ROUTERS);
            ipStack.sendPacket(ipp, null);
        } else if (ipStack.isRouter() && nextRA < time) {
            nextRA = time + 10000;
        }

    }

    public void receiveNDMessage(IPv6Packet packet) {
        /* payload is a ICMP6 packet */
        ICMP6Packet payload = (ICMP6Packet) packet.getIPPayload();
        Neighbor nei = null;
        switch (payload.type) {
        case ICMP6Packet.ROUTER_SOLICITATION:
            nei = neigborTable.addNeighbor(packet.sourceAddress, packet.getLinkSource());
            if (nei != null) {
                nei.setState(Neighbor.REACHABLE);
            }

            if (ipStack.isRouter()) {
                sendRA(packet);
            }
            break;
        case ICMP6Packet.ROUTER_ADVERTISEMENT:
            nei = neigborTable.addNeighbor(packet.sourceAddress, packet.getLinkSource());
            neigborTable.setDefrouter(nei);
            nei.setState(Neighbor.REACHABLE);
            break;
        }
    }

    private void sendRA(IPv6Packet packet) {
        ICMP6Packet payload = (ICMP6Packet) packet.getIPPayload();
        ICMP6Packet p = new ICMP6Packet();
        p.targetAddress = payload.targetAddress;
        p.type = ICMP6Packet.ROUTER_ADVERTISEMENT;
        p.flags = ICMP6Packet.FLAG_SOLICITED | ICMP6Packet.FLAG_OVERRIDE;

        /* ensure that the RA is updated... */
        p.updateRA(ipStack);

        IPv6Packet ipp = new IPv6Packet();
        ipp.setIPPayload(p);
        // is this ok?
        //ipp.destAddress = packet.sourceAddress;
        ipp.destAddress = packet.sourceAddress != null ? packet.sourceAddress : IPStack.ALL_NODES;
        ipp.sourceAddress = ipStack.myLocalIPAddress;
        System.out.print("Created ICMP6 RA for ");
        Formatter f = new Formatter(System.out);
        IPv6Packet.printAddress(f, ipp.destAddress);
        System.out.print(" ");
        packet.printPacket(f);

        ipStack.sendPacket(ipp, packet.netInterface);
    }
}
