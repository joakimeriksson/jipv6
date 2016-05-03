package se.sics.jipv6.analyzer;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;

public class Node {

    public HashMap<String, Object> properties = new HashMap<String,Object>();
    public ArrayList<String> ipAddresses = new ArrayList<String>();
    public ArrayList<String> macAddresses = new ArrayList<String>();

    /* MAC packet */
    public int packetSent;
    public int packetReceived;
    public int seqNo; /* the last seqNo of a packet sent towards the node */


    public void print(PrintWriter printWriter) {
        printWriter.print("Node - MAC:");
        for(String mac : macAddresses) {
            printWriter.print("  " + mac);
        }
        printWriter.print("   IP:");
        for(String ip : ipAddresses) {
            printWriter.print("  " + ip);
        }
        printWriter.println("\n   Sent/Received => sent: " + packetSent + " recv: " + packetReceived);
        for(String key : properties.keySet()) {
            printWriter.println("   " + key + " => " + properties.get(key).toString());
        }
    }

}
