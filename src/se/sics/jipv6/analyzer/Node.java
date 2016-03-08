package se.sics.jipv6.analyzer;

import java.util.ArrayList;
import java.util.HashMap;

public class Node {
    
    public HashMap<String, Object> properties;
    public ArrayList<String> ipAddresses = new ArrayList<String>();
    public ArrayList<String> macAddresses = new ArrayList<String>();

    /* MAC packet */
    public int packetSent;
    public int packetReceived;
    public int seqNo; /* the last seqNo of a packet sent towards the node */

    
    public void print() {
        System.out.print("Node - MAC:");
        for(String mac : macAddresses) {
            System.out.print("  " + mac);
        }
        System.out.print("   IP:");
        for(String ip : ipAddresses) {
            System.out.print("  " + ip);            
        }
        System.out.println("\n   sent: " + packetSent + " recv: " + packetReceived);
    }

}
