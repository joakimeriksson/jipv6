package se.sics.jipv6.analyzer;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.UnknownHostException;

import se.sics.jipv6.core.HC06Packeter;
import se.sics.jipv6.core.HopByHopOption;
import se.sics.jipv6.core.ICMP6Packet;
import se.sics.jipv6.core.IPv6ExtensionHeader;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.Packet;
import se.sics.jipv6.core.UDPPacket;
import se.sics.jipv6.mac.IEEE802154Handler;
import se.sics.jipv6.util.SerialRadioConnection;
import se.sics.jipv6.util.Utils;

public class TestSniff {
    /* Run JIPv6 over TUN on linux of OS-X */

    PacketAnalyzer analyzer;
    IEEE802154Handler i154Handler;
    HC06Packeter hc06Packeter;
    SerialRadioConnection serialRadio;

    public TestSniff(PacketAnalyzer a) {
        analyzer = a;
        i154Handler = new IEEE802154Handler();
        hc06Packeter = new HC06Packeter();
        hc06Packeter.setContext(0, 0xaaaa0000, 0, 0, 0);
    }

    public void connect(String host) throws UnknownHostException, IOException {
        serialRadio = new SerialRadioConnection();
        serialRadio.connect(host);
        serialRadio.send("?C");
    }
    
    public void packetData(byte[] data) {
        Packet packet = new Packet();
        packet.setBytes(data);
        i154Handler.packetReceived(packet);
        //    packet.printPacket();
        //    i154Handler.printPacket(System.out, packet);
        if (analyzer != null) {
            analyzer.analyzePacket(packet);
        }

        if (packet.getPayloadLength() > 1 && 
                packet.getAttributeAsInt(IEEE802154Handler.PACKET_TYPE) == IEEE802154Handler.DATAFRAME) {
            IPv6Packet ipPacket = new IPv6Packet(packet);
            int dispatch = packet.getData(0);
            packet.setAttribute("6lowpan.dispatch", dispatch);
            if (hc06Packeter.parsePacketData(ipPacket)) {
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
                            udpPacket.parsePacketData(ipPacket);
                            if (extHeader != null) {
                                extHeader.setNext(udpPacket);
                            } else {
                                ipPacket.setIPPayload(udpPacket);
                            }
                            //                        System.out.println("UDP Packet handled...");
                            udpPacket.printPacket(System.out);
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
                        icmp6Packet.printPacket(System.out);
                        more = false;
                    default:
                        more = false;
                    }
                }
                if (analyzer != null) {
                    analyzer.analyzeIPPacket(ipPacket);
                }
            }
        } 
    }


    public static void main(String[] args) throws ClassNotFoundException, InstantiationException, 
    IllegalAccessException, UnknownHostException, IOException {
        Class<?> paClass = Class.forName(args[0]);
        PacketAnalyzer analyzer = (PacketAnalyzer) paClass.newInstance();
        TestSniff sniff = new TestSniff(analyzer);
        if(args.length > 1) {
            sniff.connect(args[1]);
        }
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
        String line;
        try {
            while (true) {
                line = input.readLine();
                if (line != null && line.startsWith("h:")) {
                    /* HEX packet input */
                    byte[] data = Utils.hexconv(line.substring(2));
                    // Print this if verbose?
                    //                    System.out.printf("Got packet of %d bytes\n", data.length);
                    //                    System.out.println(line);
                    sniff.packetData(data);
                }
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

}
