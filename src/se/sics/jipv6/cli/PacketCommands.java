/**
 * Copyright (c) 2008-2016, Swedish Institute of Computer Science.
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
 * -----------------------------------------------------------------
 *
 * MiscCommands
 *
 * Author  : Joakim Eriksson
 * Created : 6 may 2016
 */

package se.sics.jipv6.cli;

import org.kohsuke.args4j.Argument;

import se.sics.jipv6.analyzer.JShark;
import se.sics.jipv6.pcap.CapturedPacket;
import se.sics.jipv6.util.Utils;

public class PacketCommands {
    private PacketCommands() {
        // Prevent instances of this class
    }
    
    @CLICommand(name="hexinput", topic="packets", description="input a hex packet")
    public static class HexinCommand implements Command {

        @Argument(usage="hexpacket", metaVar="PACKET", required=true)
        private String hexdata;

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            context.out.println("Receive:" + hexdata);
            byte[] packetData = Utils.hexconv(hexdata);
            CapturedPacket packet = new CapturedPacket(System.currentTimeMillis(), packetData);
            JShark.getJShark().packetData(packet);
            return 0;
        }
    }

    @CLICommand(name="storepackets", topic="packets", description="set store or not store packets")
    public static class StorePacketsCommand implements Command {

        @Argument(usage="storepackets", metaVar="CMD")
        private String cmd;

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            JShark js = JShark.getJShark();
            if (cmd == null) cmd = "";
            if (cmd.equals("true") || cmd.equals("1")) {
                context.out.println("Storing packets.");
                js.setStorePackets(true);
            } else if (cmd.equals("false") || cmd.equals("0")) {
                context.out.println("Not storing packets.");
                js.setStorePackets(false);
            } else if (cmd.equals("clear")) {
                js.getPacketStore().clear();
            } else {
                context.out.println("PacketStore: store:" + js.isStoringPackets() + " PacketCount:" + js.getPacketStore().getNumberOfPackets());
            }
            return 0;
        }
    }

}
