package se.sics.jipv6.util;

import java.util.ArrayList;
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
        if(index > startPos && index < pos + startPos) {
            return currentPackets[index];
        }
        if(index < startPos) {
            CapturedPacket[] block = packets.get(index / PACKETS_PER_BLOCK);
            return block[index % PACKETS_PER_BLOCK];
        }
        /* Not there??? */
        return null;
    }

    public void clear() {
        pos = 0;
        startPos = 0;
        packets.clear();
    }
}
