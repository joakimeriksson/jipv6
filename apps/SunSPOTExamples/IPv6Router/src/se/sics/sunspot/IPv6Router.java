/*
 * Author: Joakim Eriksson, SICS
 * IPv6 router for the Sun SPOT
 *
 * Will use some "binary" protocol for communication with a host app.?
 *
 * Will handle HC01 compressed IPv6 packets over 6lowpan (802.15.4).
 */

package se.sics.sunspot;

import javax.microedition.io.*;

import se.sics.jipv6.core.AbstractPacketHandler;
import se.sics.jipv6.core.HC01Packeter;
import se.sics.jipv6.core.IPStack;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.NetworkInterface;
import se.sics.jipv6.core.Packet;
import se.sics.jipv6.tunnel.TSPClient;

import com.sun.spot.peripheral.radio.I802_15_4_MAC;
import com.sun.spot.peripheral.radio.ILowPan;
import com.sun.spot.peripheral.radio.IProtocolManager;
import com.sun.spot.peripheral.radio.LowPan;
import com.sun.spot.peripheral.radio.LowPanHeaderInfo;
import com.sun.spot.peripheral.radio.RadioFactory;
import com.sun.spot.peripheral.radio.RadioPacket;
import com.sun.spot.util.IEEEAddress;

/**
 *
 * @author: Joakim Eriksson
 */
public class IPv6Router {

    private static final short PAN_ID = (short)0xabcd;
    private ILowPan lpan;
    private IPStack ipStack;
    private HC01Packeter hc01Packeter = new HC01Packeter();
    private I802_15_4_MAC mac = null;

    char[] hex = "0123456789ABCDEF".toCharArray();
    private final static byte[] bc = new byte[] {(byte)0xff, (byte)0xff};

    /* TSPClient info */
    private String user;
    private String pwd;
    private String host;

    public IPv6Router(String host, String user, String pwd) {
        this.host = host;
        this.user = user;
        this.pwd = pwd;
    }

    private byte[] addrToByte(long addr) {
        if (addr == 0xffff) {
            return bc;
        } else {
            byte[] byteAddr = new byte[8];
            for (int i = 0, n = 8; i < n; i++) {
                byteAddr[7 - i] = (byte) (addr & 0xff);
                addr = addr >> 8;
            }
            return byteAddr;
        }
    }

    private long addrToLong(byte[] addr) {
        long addrL = 0;
        for (int i = 0, n = addr.length; i < n; i++) {
            addrL = addrL << 8;
            addrL = addrL | (addr[i] & 0xff);
        }
        return addrL;
    }

    IProtocolManager hc01Manager = new IProtocolManager() {
        public void processIncomingData(byte[] payload, LowPanHeaderInfo headerInfo) {
            System.out.println("**** LowPan: PACKET RECEIVED!!!");
            IPv6Packet ipPacket = new IPv6Packet();
            ipPacket.setBytes(payload);
            /* should be enough with Source and Dest of LL */
            ipPacket.setAttribute(Packet.LL_SOURCE,
                    addrToByte(headerInfo.sourceAddress));
            ipPacket.setAttribute(Packet.LL_DESTINATION,
                    addrToByte(headerInfo.destinationAddress));
            hc01Packeter.parsePacketData(ipPacket);
            ipPacket.netInterface = macHandler;
            ipStack.receivePacket(ipPacket);
        }
    };

    private class MACHandler extends AbstractPacketHandler implements NetworkInterface {
        public void setIPStack(IPStack stack) {}
        public String getName() {
            return "802_15_4";
        }

        public boolean isReady() {
            return true;
        }

        public void packetReceived(Packet packet) {}
        public void sendPacket(Packet packet) {
            sendPacket((IPv6Packet) packet);
        }

        public void sendPacket(IPv6Packet packet) {
            /* here we got a packet from the 802.15.4 handler */
            byte[] data = ipStack.getPacketer().generatePacketData((IPv6Packet)packet);
            byte[] dest = packet.getLinkDestination();

            RadioPacket radioPacket;
            if ((dest[0] == (byte) 0xff) && (dest[1] == (byte) 0xff)) {
                radioPacket = RadioPacket.getBroadcastPacket();
            } else {
                radioPacket = RadioPacket.getDataPacket();
                radioPacket.setDestinationAddress(addrToLong(dest));
            }

            radioPacket.setDestinationPanID(PAN_ID);
            radioPacket.setSourceAddress(addrToLong(packet.getLinkSource()));
            radioPacket.setMACPayloadLength(data.length + 1);
            radioPacket.setMACPayloadAt(0, (byte)0x03);
            for (int i = 0, n = data.length; i < n; i++) {
                radioPacket.setMACPayloadAt(i + 1, data[i]);
            }
            mac.mcpsDataRequest(radioPacket);
        }
    }

    MACHandler macHandler = new MACHandler();

    private void run() throws Exception {
        long ieeeAddress = RadioFactory.getRadioPolicyManager().getIEEEAddress();
        IEEEAddress address = new IEEEAddress(ieeeAddress);
        byte[] macAddr = addrToByte(address.asLong());

        System.out.println("Starting IPv6Router application on " + address + " ...");

        try {
            // Open up a broadcast connection to the host port
            // where the 'on Desktop' portion of this demo is listening
            lpan = LowPan.getInstance();
            System.out.println("Low pan - registering protocol manager: " + lpan);
            lpan.registerProtocolFamily((byte)0x03, hc01Manager);

            mac = RadioFactory.getI802_15_4_MAC();
            mac.mlmeStart(PAN_ID, 24);
            mac.mlmeSet(I802_15_4_MAC.MAC_RX_ON_WHEN_IDLE, 1);
        } catch (Exception e) {
            System.err.println("Caught " + e + " in connection initialization.");
            e.printStackTrace();
            System.exit(1);
        }

        ipStack = new IPStack();
        ipStack.setLinkLayerAddress(macAddr);
        ipStack.setLinkLayerHandler(macHandler);
        ipStack.setRouter(true);

        TSPClient tunnel = TSPClient.startTSPTunnel(ipStack, host, user, pwd);
        ipStack.setTunnel(tunnel);

        System.out.println("IP Stack started (router)");
    }

    /**
     * Start up the host application.
     *
     * @param args any command line arguments
     */
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("Please give host, username and password as arguments.");
            return;
        }
        IPv6Router app = new IPv6Router(args[0], args[1], args[2]);
        app.run();
    }
}
