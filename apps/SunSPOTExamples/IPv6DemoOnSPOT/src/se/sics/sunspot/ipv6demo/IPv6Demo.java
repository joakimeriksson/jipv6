/*
 * IPv6Demo
 *
 * Copyright (c) 2009 SICS
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package se.sics.sunspot.ipv6demo;

import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;

import javax.microedition.midlet.MIDlet;
import javax.microedition.midlet.MIDletStateChangeException;
import se.sics.jipv6.core.AbstractPacketHandler;
import se.sics.jipv6.core.IPHCPacketer;
import se.sics.jipv6.http.HttpServer;
import se.sics.jipv6.http.HttpServlet;
import se.sics.jipv6.http.HttpServletRequest;
import se.sics.jipv6.http.HttpServletResponse;
import se.sics.jipv6.core.ICMP6Packet;
import se.sics.jipv6.core.IPPayload;
import se.sics.jipv6.core.IPStack;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.NetworkEventListener;
import se.sics.jipv6.core.NetworkInterface;
import se.sics.jipv6.core.Packet;
import se.sics.jipv6.core.TCPConnection;
import se.sics.jipv6.core.TCPListener;
import se.sics.jipv6.core.TCPPacket;
import se.sics.jipv6.core.UDPPacket;
import se.sics.sunspot.cli.CommandHandler;
import se.sics.sunspot.ipv6demo.CLISession;
import se.sics.sunspot.ipv6demo.LedsCommand;

import com.sun.spot.peripheral.radio.I802_15_4_MAC;
import com.sun.spot.peripheral.radio.ILowPan;
import com.sun.spot.peripheral.radio.IProtocolManager;
import com.sun.spot.peripheral.radio.LowPan;
import com.sun.spot.peripheral.radio.LowPanHeaderInfo;
import com.sun.spot.peripheral.radio.RadioFactory;
import com.sun.spot.peripheral.radio.RadioPacket;
import com.sun.spot.sensorboard.EDemoBoard;
import com.sun.spot.sensorboard.peripheral.IAccelerometer3D;
import com.sun.spot.sensorboard.peripheral.ILightSensor;
import com.sun.spot.sensorboard.peripheral.ITemperatureInput;
import com.sun.spot.sensorboard.peripheral.ITriColorLED;
import com.sun.spot.util.IEEEAddress;

/**
 * This application is the 'on SPOT' portion of the SendDataDemo. It
 *
 * @author: Joakim Eriksson, SICS
 */
public class IPv6Demo extends MIDlet {

    private static byte[] IPSO_SERVER = new byte[] {
            0x20, 0x01, 0x04, 0x20,
            0x5f, (byte) 0xff, 0x00, 0x7d,
            0x02, (byte) 0xd0, (byte)0xb7, (byte)0xff,
            (byte)0xfe, 0x23, (byte)0xe6, (byte)0xdb};
    private static final int IPSO_PORT = 61616;
    private static final int IPSO_INTERVAL = 60;

    private static final short PAN_ID = (short)0xabcd;
    private ILowPan lpan;
    private IPStack ipStack;
    private IPHCPacketer iphcPacketer = new IPHCPacketer();
    private I802_15_4_MAC mac = null;
    private final ITriColorLED[] leds = EDemoBoard.getInstance().getLEDs();
    final ILightSensor lightSensor = EDemoBoard.getInstance().getLightSensor();
    final ITemperatureInput temperatureSensor = EDemoBoard.getInstance().getADCTemperature();
    final IAccelerometer3D accelerometerSensor = EDemoBoard.getInstance().getAccelerometer();
    char[] hex = "0123456789ABCDEF".toCharArray();
    int ledsStatus = 0;

    private final static byte[] bc = new byte[] {(byte)0xff, (byte)0xff};

    private CommandHandler commandHandler;
    private IPSOHandler ipsoHandler;

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

    NetworkEventListener listener = new NetworkEventListener() {
        public void packetHandled(IPv6Packet packet) {
            IPPayload pl = packet.getIPPayload();
            if (pl instanceof ICMP6Packet) {
                ICMP6Packet icmp = (ICMP6Packet) pl;
                /* flash leds if getting a ping6 */
                if (icmp.getType() == ICMP6Packet.ECHO_REQUEST) {
                    for (int i = 0, n = 8; i < n; i++) {
                        leds[i].setRGB(255, 255, 255);
                        leds[i].setOn();
                    }
                    try {
                        Thread.sleep(10);
                    } catch (Exception e) {
                    }
                    for (int i = 0, n = 8; i < n; i++) {
                        leds[i].setOff();
                    }
                    try {
                        Thread.sleep(10);
                    } catch (Exception e) {
                    }
                    updateLeds();
                }
            }
        }
    };

    void updateLeds() {
        for (int i = 0, n = 4; i < n; i++) {
            if (ledsStatus == 1) {
                leds[i].setRGB(255, 255, 255);
                leds[i].setOn();
            } else {
                leds[i].setOff();
            }
        }
    }

    IProtocolManager iphcManager = new IProtocolManager() {
        public void processIncomingData(byte[] payload, LowPanHeaderInfo headerInfo) {
            System.out.println("LowPan: PACKET RECEIVED!!!");
            IPv6Packet ipPacket = new IPv6Packet();
            ipPacket.setBytes(payload);
            /* should be enough with Source and Dest of LL */
            ipPacket.setAttribute(Packet.LL_SOURCE,
                    addrToByte(headerInfo.sourceAddress));
            ipPacket.setAttribute(Packet.LL_DESTINATION,
                    addrToByte(headerInfo.destinationAddress));
            iphcPacketer.parsePacketData(ipPacket);
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

            /* -1 or lenght? */
            //	try {
            //	    lpan.send((byte)3, (byte)0, addrToLong(dest), data, 0, data.length - 1, true);
            //	} catch (Exception  e) {
            //	    e.printStackTrace();
            //	}

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
            /* remove ack request... since we do not handle that currently -
             *  works on data packets...*/
            //	try {
            //	  radioPacket.setMACPayloadAt(-21, (byte) (radioPacket.getMACPayloadAt(-21) & (~0x20)));
            //	} catch (Exception e) {}
            mac.mcpsDataRequest(radioPacket);
        }
    }

    MACHandler macHandler = new MACHandler();
    protected CommandHandler commandHander;

    protected void startApp() throws MIDletStateChangeException {

        IEEEAddress address = new IEEEAddress(System.getProperty("IEEE_ADDRESS"));
        long extendedAddress = address.asLong();
        //    extendedAddress = (extendedAddress & 0xfcffffffL);
        byte[] macAddr = addrToByte(address.asLong());

        System.out.println("Starting IPv6 Demo application on " + address + " ...");
        new com.sun.spot.util.BootloaderListener().start();       // Listen for downloads/commands over USB connection

        ipStack = new IPStack();
        ipStack.setLinkLayerAddress(macAddr);
        ipStack.setLinkLayerHandler(macHandler);
        ipStack.setNetworkEventListener(listener);
        System.out.println("IP Stack started");

        HttpServer server = new HttpServer(ipStack);

        commandHandler = new CommandHandler(System.out, System.err);
        commandHandler.registerCommand("leds", new LedsCommand());
        commandHandler.registerCommand("sense", new SenseCommand());
        commandHandler.registerCommand("d", new DisplayCommand());
        commandHandler.registerCommand("ipinfo", new IPInfo(ipStack, server));
        /* setup telnet port and CLI */
        TCPConnection conn = ipStack.listen(23);
        conn.setTCPListener(new TCPListener() {
            public void connectionClosed(TCPConnection connection) {}
            public void newConnection(final TCPConnection connection) {
                new CLISession(commandHandler, connection.getInputStream(),
                        connection.getOutputStream());
            }
            public void tcpDataReceived(TCPConnection source, TCPPacket packet) {
            }});

        ipsoHandler = new IPSOHandler(ipStack, this);
        try {
            ipStack.listen(ipsoHandler, 0xf0b0);
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        server.registerServlet("/", new HttpServlet() {
            int access = 0;
            public void service(HttpServletRequest req, HttpServletResponse resp) {
                PrintStream out = new PrintStream(resp.getOutputStream());
                out.print("HTTP/1.0 200 OK\r\n\r\n");
                out.println("<html><body>");
                out.println("<h1>Testing SunSPOT HTTP server</h1>");
                out.println("This is a basic test servlet running on a Sun SPOT!");
                out.println("It runs on top of the jIPv6 TCP/IP stack.");
                out.println("<br><br><em>Access counter: " + (access++) + "</em>");
                out.println("</body></html>");
                out.flush();
            }
        });

        server.registerServlet("/sensors", new HttpServlet() {
            public void service(HttpServletRequest req, HttpServletResponse resp) {
                PrintStream out = new PrintStream(resp.getOutputStream());
                out.print("HTTP/1.0 200 OK\r\n\r\n");
                out.println("<html><body>");
                out.println("<h1>SunSPOT Sensors</h1>");
                try {
                    out.println("Temp: " + temperatureSensor.getCelsius() + "<br>");
                    out.println("Light: " + lightSensor.getValue() + "<br>");
                    out.println("Acc: " + accelerometerSensor.getAccelX() + ","
                            + accelerometerSensor.getAccelY() + ","
                            + accelerometerSensor.getAccelZ() + "<br>");
                } catch (IOException e) {
                }
                out.println("</body></html>");
                out.flush();
            }
        });


        try {
            // Open up a broadcast connection to the host port
            // where the 'on Desktop' portion of this demo is listening
            lpan = LowPan.getInstance();
            System.out.println("Low pan - registering protocol manager: " + lpan);
            lpan.registerProtocolFamily((byte)0x03, iphcManager);

            mac = RadioFactory.getI802_15_4_MAC();
            mac.mlmeStart(PAN_ID, 24);
            mac.mlmeSet(I802_15_4_MAC.MAC_RX_ON_WHEN_IDLE, 1);
        } catch (Exception e) {
            System.err.println("Caught " + e + " in connection initialization.");
            e.printStackTrace();
            System.exit(1);
        }

        int send = 0;
        while (true) {
            try {
                if (ipStack.getNeighborTable().getDefrouter() == null) {
                    leds[7].setRGB(255, 0, 0);
                } else {
                    leds[7].setRGB(100, 255, 100);
                }
                leds[7].setOn();
                Thread.sleep(2);
                leds[7].setOff();

                Thread.sleep(500);
                send++;
                /* post a message to the IPSO server each minute */
                if (send == IPSO_INTERVAL) {
                    UDPPacket udp = new UDPPacket();
                    udp.setDestinationPort(IPSO_PORT);
                    udp.setSourcePort(IPSO_PORT);
                    double t = temperatureSensor.getCelsius();
                    udp.setPayload(("T" + (int)t + "." + (int) (t/10)).getBytes());
                    IPv6Packet ipp = new IPv6Packet(udp);
                    ipp.setDestinationAddress(IPSO_SERVER);
                    ipp.setSourceAddress(ipStack.getIPAddress());
                    ipStack.sendPacket(ipp, macHandler);
                    send = 0;
                }
            } catch (Exception e) {
                System.err.println("Caught " + e + " while collecting/sending sensor sample.");
                e.printStackTrace();
            }
        }
    }

    protected void pauseApp() {
        // This will never be called by the Squawk VM
    }

    protected void destroyApp(boolean arg0) throws MIDletStateChangeException {
        // Only called if startApp throws any exception other than MIDletStateChangeException
    }
}
