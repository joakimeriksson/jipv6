package se.sics.jipv6.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Arrays;

import se.sics.jipv6.yal.Encap;
import se.sics.jipv6.yal.Encap.Error;

public class SerialRadioConnection implements Runnable {

    private static int SLIP_END = 0300;
    private static int SLIP_ESC = 0333;
    private static int SLIP_ESC_END = 0334;
    private static int SLIP_ESC_ESC = 0335;
    private Socket socket;
    private InputStream input;
    private OutputStream output;
    
    byte[] buffer = new byte[1000];
    int pos;
    
    public void connect(String host) throws UnknownHostException, IOException {
        socket = new Socket(host, 9999);
        input = socket.getInputStream();
        output = socket.getOutputStream();
        new Thread(this).start();
    }

    private void handleSlipData(byte[] slipFrame) {
        Encap encap = new Encap();
        Error e = encap.parseEncap(slipFrame);
        if (e == Error.OK) {
            System.out.println("ENCAP OK! Type:" + encap.getPayloadTypeAsString());
            /* Send of data to something?? */
            byte payload[] = encap.getPayloadData();
            payload = Arrays.copyOfRange(payload, 2, payload.length);
            System.out.println("Payload (len = " + payload.length + ")");
            for(int i = 0; i < payload.length; i++) {
                System.out.printf("%02x", payload[i]);
            }
        }
    }
    
    public void send(byte[] data) throws IOException {
        Encap encap = Encap.createSerial(data);
        output.write(encap.generateBytes());
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
                        System.out.println("SLIP Frame received - len:" + pos);
                        handleSlipData(Arrays.copyOf(buffer, pos));
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

    public void send(String string) throws IOException {
        send(string.getBytes());
    }
}
