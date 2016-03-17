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

public class Neighbor {
    /*   From the RFC - States of the neighbors:
     *
     *   INCOMPLETE  Address resolution is in progress and the link-layer
     *   address of the neighbor has not yet been determined.
     *
     *   REACHABLE   Roughly speaking, the neighbor is known to have been
     *   reachable recently (within tens of seconds ago).
     *
     *   STALE       The neighbor is no longer known to be reachable but
     *   until traffic is sent to the neighbor, no attempt
     *   should be made to verify its reachability.
     *
     *   DELAY       The neighbor is no longer known to be reachable, and
     *   traffic has recently been sent to the neighbor.
     *   Rather than probe the neighbor immediately, however,
     *   delay sending probes for a short while in order to
     *   give upper-layer protocols a chance to provide
     *   reachability confirmation.
     *
     *   PROBE       The neighbor is no longer known to be reachable, and
     *   unicast Neighbor Solicitation probes are being sent to
     *   verify reachability.
     *
     */

    public static final int INCOMPLETE = 0;
    public static final int REACHABLE = 1;
    public static final int STALE = 2;
    public static final int DELAY = 3;
    public static final int PROBE = 4;
    public static final int NO_STATE = 5;


    byte[] ipAddress;
    byte[] linkAddress;
    NetworkInterface netInterface;
    long reachableUntil;
    long lastNDSent;
    int state = INCOMPLETE;

    public byte[] getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(byte[] ipAddress) {
        this.ipAddress = ipAddress;
    }

    public void setState(int state) {
        this.state = state;
    }
}
