/**
 * Copyright (c) 2016, Swedish Institute of Computer Science.
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
 * JShark - a Java based packet sniffer and analyzer.
 *
 * -----------------------------------------------------------------
 *
 *
 * Author  : Joakim Eriksson
 * Created :  mar 2016
 *
 */
package se.sics.jipv6.analyzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.util.ArrayList;

import se.sics.jipv6.core.IPHCPacketer;
import se.sics.jipv6.core.HopByHopOption;
import se.sics.jipv6.core.ICMP6Packet;
import se.sics.jipv6.core.IPv6ExtensionHeader;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.MacPacket;
import se.sics.jipv6.core.UDPPacket;
import se.sics.jipv6.mac.IEEE802154Handler;
import se.sics.jipv6.pcap.CapturedPacket;
import se.sics.jipv6.pcap.PCAPWriter;
import se.sics.jipv6.util.SerialRadioConnection;
import se.sics.jipv6.util.Utils;

public class JShark {
    /* Run JIPv6 over TUN on linux of OS-X */

    public static JShark defaultJShark;
    
    ArrayList<PacketAnalyzer> analyzers = new ArrayList<PacketAnalyzer>();
    IEEE802154Handler i154Handler;
    IPHCPacketer iphcPacketer;
    SerialRadioConnection serialRadio;

    NodeTable nodeTable = new NodeTable();
    private PCAPWriter pcapOutput;
    private PrintStream out;
    
    public JShark(PacketAnalyzer a, PrintStream out) {
        analyzers.add(new MACAnalyzer());
        analyzers.add(new RPLAnalyzer());
        analyzers.add(a);
        i154Handler = new IEEE802154Handler();
        iphcPacketer = new IPHCPacketer();
        iphcPacketer.setContext(0, 0xaaaa0000, 0, 0, 0);
        this.out = out;
        setOut(out);
        if (defaultJShark == null) {
            defaultJShark = this;
        }
    }

    public static JShark getJShark() {
        return defaultJShark;
    }
    
    private void setOut(PrintStream out) {
        for (PacketAnalyzer analyzer : analyzers) {
            analyzer.init(nodeTable, out);
        }
    }
    
    public void setPrintStream(PrintStream out) {
        this.out = out;
        setOut(out);
    }
    
    public NodeTable getNodeTable() {
        return nodeTable;
    }
    
    public void connect(String host) throws UnknownHostException, IOException {
        connect(host, -1);
    }

    public void connect(String host, int port) throws UnknownHostException, IOException {
        serialRadio = new SerialRadioConnection(new SerialRadioConnection.PacketListener() {
            public void packetReceived(byte[] data) {
                CapturedPacket packet = new CapturedPacket(System.currentTimeMillis(), data);
                packetData(packet);
            }
        });
        if (port < 0) {
            serialRadio.connect(host);
        } else {
            serialRadio.connect(host, port);
        }
        // Set radio in sniff mode
        serialRadio.setRadioMode(2);
    }

    public SerialRadioConnection getSerialRadio() {
        return this.serialRadio;
    }

    public void packetData(CapturedPacket captured) {
        MacPacket packet = new MacPacket(captured.getTimeMillis());
        packet.setBytes(captured.getPayload());

        if (pcapOutput != null) {
            try {
                pcapOutput.writePacket(captured);
            } catch (IOException e) {
                System.err.println("Failed to write to PCAP file");
                e.printStackTrace();
            }
        }

        /* Allow all analyzers run on the raw packet */
        for(PacketAnalyzer analyzer: analyzers) {
            if (!analyzer.analyzeRawPacket(captured)) {
                break;
            }
        }


        i154Handler.packetReceived(packet);
        //    packet.printPacket();
        //    i154Handler.printPacket(System.out, packet);

        byte[] mac;
        Node sender = null;
        Node receiver = null;
        if((mac = packet.getLinkSource()) != null) {
            /* only nodeTable getByMAC will trigger add of new node */
            sender = nodeTable.getNodeByMAC(mac);
            sender.packetSent++;
        }
        if((mac = packet.getLinkDestination()) != null) {
            receiver = nodeTable.getNodeByMAC(mac);
            /* NOTE: this is packets sent towards... rather than actually received */
            receiver.packetReceived++;
            receiver.seqNo = packet.getAttributeAsInt(IEEE802154Handler.SEQ_NO);
        }

        for(PacketAnalyzer analyzer: analyzers) {
            if (!analyzer.analyzeMacPacket(packet, sender, receiver)) {
                System.out.println("Analyzer " + analyzer.getClass().getName() + " returned false...");
                break;
            }
        }

        if (packet.getPayloadLength() > 1 &&
                packet.getAttributeAsInt(IEEE802154Handler.PACKET_TYPE) == IEEE802154Handler.DATAFRAME) {
            IPv6Packet ipPacket = new IPv6Packet(packet);
            int dispatch = packet.getData(0);
            packet.setAttribute("6lowpan.dispatch", dispatch);
            if (iphcPacketer.parsePacketData(ipPacket)) {
                boolean more = true;
                byte nextHeader = ipPacket.getNextHeader();
                IPv6ExtensionHeader extHeader = null;
                while(more) {
                    //                System.out.printf("Next Header: %d pos:%d\n", nextHeader, ipPacket.getPos());
                    //                ipPacket.printPayload();
                    switch(nextHeader) {
                    case HopByHopOption.DISPATCH:
                        HopByHopOption hbh = new HopByHopOption();
                        hbh.parsePacketData(ipPacket);
                        ipPacket.setIPPayload(hbh);
                        extHeader = hbh;
                        nextHeader = hbh.getNextHeader();
                        break;
                    case UDPPacket.DISPATCH:
                        if (ipPacket.getIPPayload() != null && ipPacket.getIPPayload() instanceof UDPPacket) {
                            /* All done ? */
                            //                        System.out.println("All done - UDP already part of payload?");
                            more = false;
                        } else {
                            UDPPacket udpPacket = new UDPPacket();
                            try {
                                udpPacket.parsePacketData(ipPacket);
                            } catch (Exception e) {
                                System.out.println("Failed to parse UDP packet:");
                                ipPacket.printPacket();
                                ipPacket.printPacket(System.out);
                                throw e;
                            }
                            if (extHeader != null) {
                                extHeader.setNext(udpPacket);
                            } else {
                                ipPacket.setIPPayload(udpPacket);
                            }
                            //                        System.out.println("UDP Packet handled...");
                            //udpPacket.printPacket(System.out);
                            more = false;
                        }
                        break;
                    case ICMP6Packet.DISPATCH:
                        ICMP6Packet icmp6Packet = ICMP6Packet.parseICMP6Packet(ipPacket);
                        if (extHeader != null) {
                            extHeader.setNext(icmp6Packet);
                        } else {
                            ipPacket.setIPPayload(icmp6Packet);
                        }
                        //                    System.out.println("ICMP6 packet handled...");
                        //icmp6Packet.printPacket(System.out);
                        more = false;
                        break;
                    default:
                        more = false;
                        break;
                    }
                }
                /* Add link local destination address */
                byte[] destination = ipPacket.getDestinationAddress();
                if (IPv6Packet.isMACBased(destination, ipPacket.getLinkDestination()) ||
                        IPv6Packet.isLinkLocal(destination)) {
                    Node node = nodeTable.getNodeByIP(destination);
                    if (node == null) {
                        node = nodeTable.getNodeByMAC(ipPacket.getLinkDestination());
                        nodeTable.addIPAddr(node, destination);
                    }
                }
                byte[] source = ipPacket.getSourceAddress();
                if (IPv6Packet.isMACBased(source, ipPacket.getLinkSource()) ||
                        IPv6Packet.isLinkLocal(source)) {
                    Node node = nodeTable.getNodeByIP(source);
                    if (node == null) {
                        node = nodeTable.getNodeByMAC(ipPacket.getLinkSource());
                        nodeTable.addIPAddr(node, source);
                    }
                }

                for(PacketAnalyzer analyzer: analyzers) {
                    if (!analyzer.analyzeIPPacket(ipPacket, sender, receiver)) {
                        break;
                    }
                }
            }
        }
    }

    public void setPCAPOutFile(String outfile) throws IOException {
        this.pcapOutput = new PCAPWriter(outfile);
        this.pcapOutput.setAddingCRC(true);
    }

    public static void main(String[] args) throws ClassNotFoundException, InstantiationException,
    IllegalAccessException, UnknownHostException, IOException {
        PacketAnalyzer analyzer = null;
        if (args.length > 0) {
            if ("help".equals(args[0]) || "-h".equals(args[0])) {
                System.out.println("Usage: " + JShark.class.getSimpleName() + " [packetanalyzer] [host]");
                System.exit(0);
            }
            Class<?> paClass = Class.forName(args[0]);
            analyzer = (PacketAnalyzer) paClass.newInstance();
        } else {
            String analyserClassName = getJarManifestProperty("DefaultPacketAnalyzer");
            if (analyserClassName != null) {
                System.out.println("Using analyzer " + analyserClassName);
                Class<?> paClass = Class.forName(analyserClassName);
                analyzer = (PacketAnalyzer) paClass.newInstance();
            }
        }
        if (analyzer == null) {
            analyzer = new ExampleAnalyzer();
        }
        JShark sniff = new JShark(analyzer, System.out);
        if(args.length > 1) {
            sniff.connect(args[1]);
        } else {
            sniff.connect("localhost");
        }
        sniff.runCLI();
    }

    public void runCLI() {
        /* NOTE: supports input of HEX packets via h:.... other than that is commands */
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
        String line;
        try {
            while (true) {
                line = input.readLine();
                if (line == null) {
                    // End of input
                    break;
                }
                if (line.startsWith("h:")) {
                    /* HEX packet input */
                    byte[] data = Utils.hexconv(line.substring(2));
                    // Print this if verbose?
                    //                    System.out.printf("Got packet of %d bytes\n", data.length);
                    //                    System.out.println(line);
                    CapturedPacket packet = new CapturedPacket(System.currentTimeMillis(), data);
                    this.packetData(packet);
                } else {
                    /* Handle some very basic commands - needs improvement - steal from MSPSim soon?! */
                    if (line.startsWith("set ")) {
                        String parts[] = line.split(" ");
                        if (parts.length > 2 ) {
                            if ("channel".equals(parts[1])) {
                                try {
                                    int ch = Utils.decodeInt(parts[2]);
                                    this.serialRadio.setRadioChannel(ch);
                                } catch (Exception e) {
                                    System.out.println("Failed setting channel to " + parts[2]);
                                }
                            } else {
                                System.out.println("Unhandled set command: " + line);
                            }
                        } else {
                            System.out.println("Set needs parameter and value: " + line);
                        }
                    } else if (line.startsWith("get ")) {
                        String parts[] = line.split(" ");
                        if (parts.length > 1 ) {
                            if ("channel".equals(parts[1])) {
                                byte[] data = new byte[2];
                                data[0] = '?';
                                data[1] = 'C';
                                this.serialRadio.send(data);
                            } else {
                                System.out.println("Unhandled get command: " + line);
                            }
                        } else {
                            System.out.println("Set needs parameter and value: " + line);
                        }

                    } else if (line.startsWith("print ")) {
                        String parts[] = line.split(" ");
                        if (parts.length > 1) {
                            if ("nodes".equals(parts[1])) {
                                this.nodeTable.print(new PrintWriter(System.out));
                            } else if ("stats".equals(parts[1])) {
                                for(PacketAnalyzer analyzer: analyzers) {
                                    analyzer.print();
                                }
                            }
                        }
                    } else if (line.equals("q") || line.equals("quit")) {
                        System.err.println("Exiting...");
                        System.exit(0);
                    }
                }
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    static String getJarManifestProperty(String property) {
        Class<?> C = new Object() { }.getClass().getEnclosingClass();
        String retval = null;
        String className = C.getSimpleName() + ".class";
        String classPath = C.getResource(className).toString();
        if (!classPath.toLowerCase().startsWith("jar")) {
            return retval;
        }
        String manifestPath = classPath.substring(0, classPath.lastIndexOf("!") + 1) + "/META-INF/MANIFEST.MF";
        java.util.jar.Manifest manifest = null;
        try {
            manifest = new java.util.jar.Manifest(new java.net.URL(manifestPath).openStream());
        } catch (MalformedURLException e) {
            return retval;
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (manifest == null) {
            return retval;
        }
        java.util.jar.Attributes attr = manifest.getMainAttributes();
        String S = attr.getValue(property);
        if ((S != null) && (S.length() > 0)) {
            return S;
        }
        return retval;
    }

}
