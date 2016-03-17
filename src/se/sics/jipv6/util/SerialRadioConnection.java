package se.sics.jipv6.util;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;

import se.sics.jipv6.yal.Encap;
import se.sics.jipv6.yal.ParseException;

public class SerialRadioConnection implements Runnable {

    private static boolean DEBUG = false;

    private static final int SLIP_END = 0300;
    private static final int SLIP_ESC = 0333;
    private static final int SLIP_ESC_END = 0334;
    private static final int SLIP_ESC_ESC = 0335;
    private static final int DEBUG_LINE_MARKER = '\r';

    private Socket socket;
    private InputStream input;
    private OutputStream output;

    byte[] buffer = new byte[1000];
    int pos;

    public interface PacketListener {
        public void packetReceived(byte[] data);
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
                        listener.packetReceived(payload);
                    }
                    break;
                case 'C':
                    System.out.println("Radio channel is " + (int)(payload[2] & 0xff));
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

    public void setRadioMode(int mode) throws IOException {
        byte[] data = new byte[3];
        data[0] = '!';
        data[1] = 'm';
        data[2] = (byte)(mode & 0xff);
        send(data);
    }

}
