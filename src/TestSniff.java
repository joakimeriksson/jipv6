import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import se.sics.jipv6.core.HC06Packeter;
import se.sics.jipv6.core.HopByHopOption;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.Packet;
import se.sics.jipv6.mac.IEEE802154Handler;
import se.sics.jipv6.util.Utils;

public class TestSniff {
    /* Run JIPv6 over TUN on linux of OS-X */
    
    
    public static void main(String[] args) {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
        String line;
        IEEE802154Handler i154Handler = new IEEE802154Handler();
        HC06Packeter hc06Packeter = new HC06Packeter();
        hc06Packeter.setContext(0, 0xaaaa0000, 0, 0, 0);
        try {
            while (true) {
                line = input.readLine();
                if (line != null && line.startsWith("h:")) {
                    /* HEX packet input */
                    byte[] data = Utils.hexconv(line.substring(2));
                    System.out.printf("Got packet of %d bytes\n", data.length);
                    System.out.println(line);
                    Packet packet = new Packet();
                    packet.setBytes(data);
                    i154Handler.packetReceived(packet);
//                    packet.printPacket();
//                    i154Handler.printPacket(System.out, packet);
                    if (packet.getPayloadLength() > 1 && 
                            packet.getAttributeAsInt(IEEE802154Handler.PACKET_TYPE) == IEEE802154Handler.DATAFRAME) {
                        IPv6Packet ipPacket = new IPv6Packet(packet);
                        int dispatch = packet.getData(0);
                        packet.setAttribute("6lowpan.dispatch", dispatch);
                        System.out.printf("Dispatch: %02x\n", dispatch & 0xff);
                        hc06Packeter.parsePacketData(ipPacket);
                        boolean more = true;
                        byte nextHeader = ipPacket.getNextHeader();
                        while(more) {
                            System.out.printf("Next Header: %d\n", nextHeader);
                            switch(nextHeader) {
                            case HopByHopOption.DISPATCH:
                                HopByHopOption hbh = new HopByHopOption();
                                hbh.parsePacketData(ipPacket);
                                ipPacket.setIPPayload(hbh);
                                nextHeader = hbh.getNextHeader();
                                break;
                            default:
                                more = false;
                            }
                        }
                    } 
                }
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
