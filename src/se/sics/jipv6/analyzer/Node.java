package se.sics.jipv6.analyzer;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map.Entry;

public class Node {

    public HashMap<String, Object> properties = new HashMap<String,Object>();
    public ArrayList<String> ipAddresses = new ArrayList<String>();
    public ArrayList<String> macAddresses = new ArrayList<String>();

    /* MAC packet */
    public int packetSent;
    public int packetReceived;
    public int seqNo; /* the last seqNo of a packet sent towards the node */

    public Object getProperty(String key) {
        return properties.get(key);
    }

    public Object getProperty(String key, Object defaultValue) {
        Object v = properties.get(key);
        if (v != null) {
            return v;
        }
        return defaultValue;
    }

    public <T> T getProperty(Class<T> type, String key) {
        return getProperty(type, key, null);
    }

    public <T> T getProperty(Class<T> type, String key, T defaultValue) {
        Object v = this.properties.get(key);
        if (type.isInstance(v)) {
            return type.cast(v);
        }
        return defaultValue;
    }

    public Object putProperty(String key, Object value) {
        if (value == null) {
            return properties.remove(key);
        } else {
            return properties.put(key, value);
        }
    }

    public void setProperty(String key, Object value) {
        if (value == null) {
            properties.remove(key);
        } else {
            properties.put(key, value);
        }
    }

    public void print(PrintWriter printWriter) {
        printWriter.print("Node - MAC:");
        for(String mac : macAddresses) {
            printWriter.print("  " + mac);
        }
        printWriter.print("   IP:");
        for(String ip : ipAddresses) {
            printWriter.print("  " + ip);
        }
        printWriter.println();
        printWriter.println("   Sent/Received => sent: " + packetSent + " recv: " + packetReceived);
        for(Entry<String,Object> e : properties.entrySet()) {
            printWriter.println("   " + e.getKey() + " => " + e.getValue());
        }
    }

}
