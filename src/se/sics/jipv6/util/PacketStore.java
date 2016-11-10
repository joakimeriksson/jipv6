package se.sics.jipv6.util;

import java.util.ArrayList;
import java.util.HashMap;

import se.sics.jipv6.core.MacPacket;
import se.sics.jipv6.pcap.CapturedPacket;

public class PacketStore {

    private static int PACKETS_PER_BLOCK = 100;
    
    ArrayList<CapturedPacket[]> packets = new ArrayList<CapturedPacket[]>();
    
    int pos = 0;
    int startPos = 0;
    CapturedPacket[] currentPackets = new CapturedPacket[PACKETS_PER_BLOCK];
    
    /* Packets are assumed to be in time-stamp order and only added one at a time - e.g. no multipe
     * adders... */
    public void storePacket(CapturedPacket p) {
        currentPackets[pos] = p;
        pos++;
        if(pos == PACKETS_PER_BLOCK) {
           packets.add(currentPackets);
           currentPackets = new CapturedPacket[PACKETS_PER_BLOCK];
           pos = 0;
           startPos += PACKETS_PER_BLOCK;
        }
    }
    
    public int getNumberOfPackets() {
        return startPos + pos;
    }
    
    public CapturedPacket getPacket(int index) {
        if(index >= startPos && index < pos + startPos) {
            return currentPackets[index - startPos];
        }
        if(index < startPos) {
            CapturedPacket[] block = packets.get(index / PACKETS_PER_BLOCK);
            return block[index % PACKETS_PER_BLOCK];
        }
        /* Not there??? */
        return null;
    }

    /* This is an export function for JS data - it will produce packet data that is grouped
     * There will be a group variable group = [groups];
     * and another items = [itemas];
     *  ??? */
    public String getJSPackets() {
        StringBuffer buf = new StringBuffer();
        StringBuffer groups = new StringBuffer();
        HashMap<String, Integer> map = new HashMap<String, Integer>();
        byte[] llsource;
        String llSourceStr;
        int nextID = 1;
        Integer group = 1;
        buf.append("var items = [");
        int nPacket = getNumberOfPackets();
        long lastTime = 0;
        for(int i = 0; i < nPacket; i++) {
            CapturedPacket p = getPacket(i);
            if (i > 0) {
                buf.append(",");
            }

            if (p != null) {
                llsource = (byte[]) p.getAttribute(MacPacket.LL_SOURCE);
                if (llsource != null) {
                    llSourceStr = MacPacket.macToString(llsource);
                    group = map.get(llSourceStr);
                    if (group == null) {
                        group = ++nextID;
                        map.put(llSourceStr, group);
                    }
                } else {
                    llSourceStr = "00:00";
                    group = 0;
                }
                String content = (String) p.getAttribute("ip.type");
                if (content == null) {
                    content = "packet-" + i;
                }
                buf.append("{id:" + i).append(",group:" + group).append(",content:'" + content + "'").append(",start:" + p.getTimeMillis()).append("}\n");
                lastTime = p.getTimeMillis();
            } else {
                buf.append("{id:" + i).append(",content:'**null-packet-" + i +"'").append(",start:" + lastTime).append("}\n");
            }
        }
        buf.append("];\n");
        groups.append("var groups = [");
        boolean comma = false;
        for (String key: map.keySet()) {
            if (comma)
                groups.append(",");
            groups.append("{id:" + map.get(key)).append(",content:'" + key + "'}");
            comma = true;
        }
        groups.append("];\n");
        
        return groups.toString() + buf.toString();
    }
    
    public void clear() {
        pos = 0;
        startPos = 0;
        packets.clear();
    }
}
