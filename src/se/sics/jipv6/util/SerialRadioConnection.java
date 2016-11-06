package se.sics.jipv6.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;

import se.sics.jipv6.pcap.CapturedPacket;
import se.sics.jipv6.yal.Encap;
import se.sics.jipv6.yal.ParseException;

public class SerialRadioConnection implements Runnable {

    private static boolean DEBUG = false;

    enum PACKET_ATTRIBUTES {
        NONE,
        CHANNEL,
        LINK_QUALITY,
        RSSI,
        TIMESTAMP,
        RADIO_TXPOWER,
        LISTEN_TIME,
        TRANSMIT_TIME,
        MAX_MAC_TRANSMISSIONS,
        MAC_SEQNO,
        MAC_ACK,
    };
    
    private static long  timeDiff;
    private static final int SLIP_END = 0300;
    private static final int SLIP_ESC = 0333;
    private static final int SLIP_ESC_END = 0334;
    private static final int SLIP_ESC_ESC = 0335;
    private static final int DEBUG_LINE_MARKER = '\r';

    private Socket socket;
    private InputStream input;
    private OutputStream output;
    
    private long startTime;
    private int startSR;
    private int lastSR;
    private long lastTime;

    byte[] buffer = new byte[1000];
    int pos;

    public interface PacketListener {
        public void packetReceived(CapturedPacket packet);
    }

    PacketListener listener;

    public SerialRadioConnection(PacketListener listener) {
        this.listener = listener;
    }

    public void connect(String host) throws UnknownHostException, IOException {
        connect(host, 9999);
    }
    public void connect(String host, int port) throws UnknownHostException, IOException {
        socket = new Socket(host, port);
        input = new BufferedInputStream(socket.getInputStream());
        output = new BufferedOutputStream(socket.getOutputStream());
        new Thread(this).start();
    }

    private void handleSlipData(byte[] slipFrame) {
        if (slipFrame == null || slipFrame.length == 0) {
            return;
        }
        if ((slipFrame[0] & 0xff) == DEBUG_LINE_MARKER) {
            // Console data from serial radio
            int len = slipFrame.length - 1;
            if (slipFrame[len] == '\n') {
                len--;
            }
            if (slipFrame[len] == '\r') {
                len--;
            }
            System.out.println("SERIAL-RADIO: " + new String(slipFrame, 1, len));
            return;
        }
        try {
            Encap encap = Encap.parseEncap(slipFrame);
            if (encap.getPayloadType() != Encap.PayloadType.SERIAL) {
                // Ignore any other payload than serial data
                return;
            }
            /* Send of data to something?? */
            byte payload[] = encap.getPayloadData();
            if (DEBUG) {
                System.out.println("Payload (len = " + payload.length + "): " + Utils.bytesToHexString(payload));
            }
            if (payload.length < 3) {
                // Ignore too short packets
                return;
            }
            if (payload[0] == '!') {
                switch (payload[1]) {
                case 'h':
                    // Sniffer data
                    if (listener != null) {
                        payload = Arrays.copyOfRange(payload, 2, payload.length);
                        listener.packetReceived(new CapturedPacket(System.currentTimeMillis(), payload));
                    }
                    break;
                case 'C':
                    System.out.println("Radio channel is " + (int)(payload[2] & 0xff));
                    break;
                case 'S':
                {
                    int cnt = payload[2];
                    int pos = 3;
                    int attno = 0;
                    int attrs[] = new int[PACKET_ATTRIBUTES.values().length];
                    for(int i = 0; i < cnt; i++) {
                        PACKET_ATTRIBUTES pa = PACKET_ATTRIBUTES.values()[attno = payload[pos++]];
                        int val = ((payload[pos++] & 0xff) * 256) + (payload[pos++] & 0xff);
                        //System.out.println("Attribute: " + pa.toString() + " = " + val + " (" + ((byte) val) + ")");
                        attrs[attno] = val;
                    }
                    if (listener != null) {
                        long timeMillis = System.currentTimeMillis();
                        int srTime = attrs[PACKET_ATTRIBUTES.TIMESTAMP.ordinal()];

                        payload = Arrays.copyOfRange(payload, pos, payload.length);
                        if(startTime == 0) {
                            startTime = timeMillis;
                            startSR = srTime;
                            lastTime = startTime;
                            lastSR = srTime;
                        } else {
//                          System.out.println("LastTime" + lastTime + " SR:" + srTime + " lastSR:" + lastSR);
                            lastTime = lastTime + (srTime > lastSR ? (srTime - lastSR) : (srTime - lastSR + 0x10000));
                            lastSR = srTime;
                        }
                        
                        long srTimeMillis = lastTime;
                       // System.out.println("Time:" + srTime + " vs " + (timeMillis & 0xffff) + " Diff:" + (timeDiff / 10));
                       // System.out.println("Time Millis SR:" + srTimeMillis + " Time:" + timeMillis);
                        CapturedPacket p = new CapturedPacket(srTimeMillis, payload);
                        p.setAttribute(CapturedPacket.RSSI, new Byte((byte) attrs[PACKET_ATTRIBUTES.RSSI.ordinal()]));
                        listener.packetReceived(p);
                    }
                }
                break;
                }
            }
        } catch (ParseException e) {
            System.err.println("Error: failed to parse encap: " + e.getMessage());
            System.err.println("       0x" + Utils.bytesToHexString(slipFrame));
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error: failed to handle packet: " + e.getMessage());
            System.err.println("       0x" + Utils.bytesToHexString(slipFrame));
            e.printStackTrace();
        }
    }

    public void send(byte[] data) throws IOException {
        Encap encap = Encap.createSerial(data);
        byte[] outData = encap.generateBytes();
        for(int i = 0; i < outData.length; i++) {
            switch((int) (outData[i] & 0xff)) {
            case SLIP_END:
                output.write(SLIP_ESC);
                output.write(SLIP_ESC_END);
                break;
            case SLIP_ESC:
                output.write(SLIP_ESC);
                output.write(SLIP_ESC_ESC);
                break;
            default:
                output.write(outData[i]);
            }
        }
        output.write(SLIP_END);
        output.flush();
    }

    public void run() {
        int data;
        boolean esc = false;
        pos = 0;
        try {
            while((data = input.read()) != -1) {
                if (esc) {
                    if (data == SLIP_ESC_END) {
                        buffer[pos++] = (byte) SLIP_END;
                    } else if (data == SLIP_ESC_ESC) {
                        buffer[pos++] = (byte) SLIP_ESC;
                    } else {
                        System.out.println("Slip Error?");
                    }
                    esc = false;
                } else {
                    if (data == SLIP_END) {
                        if (pos > 0) {
                            if (DEBUG) System.out.println("SLIP Frame received - len:" + pos);
                            handleSlipData(Arrays.copyOf(buffer, pos));
                        }
                        pos = 0;
                    } else if (data == SLIP_ESC) {
                        esc = true;
                    } else {
                        //                        System.out.println("Add byte to buffer: " + data);
                        buffer[pos++] = (byte) data;
                    }
                }
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            socket.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public void setRadioChannel(int channel) throws IOException {
        byte[] data = new byte[3];
        data[0] = '!';
        data[1] = 'C';
        data[2] = (byte)(channel & 0xff);
        send(data);
    }
    
    public void setSnifferFormat(int format) throws IOException {
        byte[] data = new byte[4];
        data[0] = '!';
        data[1] = 'f';
        data[2] = 's';
        data[3] = (byte)(format & 0xff);
        send(data);
    }

    public void setRadioMode(int mode) throws IOException {
        byte[] data = new byte[3];
        data[0] = '!';
        data[1] = 'm';
        data[2] = (byte)(mode & 0xff);
        send(data);
    }

    public void setRadioPANID(int panid) throws IOException {
        byte[] data = new byte[4];
        data[0] = '!';
        data[1] = 'P';
        data[2] = (byte)((panid >> 8) & 0xff);
        data[3] = (byte)(panid & 0xff);
        send(data);
    }

}
