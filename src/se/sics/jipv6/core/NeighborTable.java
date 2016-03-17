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

/**
 * @author joakim
 *
 */
public class NeighborTable {
    // currently supports max 64 neighbors...
    Neighbor[] neighbors = new Neighbor[64];
    int neighborCount = 0;

    Neighbor defrouter;

    public synchronized Neighbor addNeighbor(byte[] ipAddress, byte[] linkAddress) {
        Neighbor nb = getNeighbor(ipAddress);
        if (nb == null) {
            if (checkIPAddress(ipAddress)) {
                nb = new Neighbor();
                nb.ipAddress = ipAddress;
                nb.linkAddress = linkAddress;
                nb.state = checkLinkAddress(linkAddress) ? Neighbor.STALE : Neighbor.INCOMPLETE;
                if (neighborCount < neighbors.length) {
                    neighbors[neighborCount++] = nb;
                } else {
                    // TODO select suitable neighbor to replace
                    neighbors[0] = nb;
                }
            }
        } else {
            /* Neighbor already in neighbor table */
            nb.linkAddress = linkAddress;
            nb.state = Neighbor.INCOMPLETE;
        }
        return nb;
    }

    private boolean checkLinkAddress(byte[] link) {
        if (link == null) return false;
        /* is there any other non-ok address ?? */
        return true;
    }
    private boolean checkIPAddress(byte[] ipAddress) {
        /* can not add unspecified IP addresses */
        if (Utils.equals(ipAddress, IPStack.UNSPECIFIED)) return false;
        /* are all other ok? */
        return true;
    }

    public Neighbor getDefrouter() {
        return defrouter;
    }

    public void setDefrouter(Neighbor neighbor) {
        defrouter = neighbor;
    }

    public synchronized boolean removeNeighbor(Neighbor nb) {
        for (int i = 0; i < neighborCount; i++) {
            if (nb == neighbors[i]) {
                // move last element forward to this position...
                neighbors[i] = neighbors[neighborCount - 1];
                neighborCount--;
                return true;
            }
        }
        return false;
    }

    public Neighbor getNeighbor(byte[] ipAddress) {
        int neighborCount0 = neighborCount;
        Neighbor[] neis = neighbors;
        for (int i = 0; i < neighborCount0; i++) {
            if (Utils.equals(ipAddress, neis[i].ipAddress)) {
                return neis[i];
            }
        }
        return null;
    }
}
