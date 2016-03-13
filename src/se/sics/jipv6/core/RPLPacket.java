package se.sics.jipv6.core;

import java.io.PrintStream;

public class RPLPacket extends ICMP6Packet {

    public static final int ICMP6_TYPE_RPL = 155;
    
    public static final int RPL_DIS = 0;
    public static final int RPL_DIO = 1;
    public static final int RPL_DAO = 2;
    public static final int RPL_DAO_ACK = 3;
    
    public static final int RPL_DAO_K_FLAG = 0x80; /* DAO ACK request */
    public static final int RPL_DAO_D_FLAG = 0x40; /* DODAG ID Present */
    
    public int instanceID;
    public int version;
    public int rank;
    public int flag;
    public int dtsn;
    public int sequence;
    public int lifetime;
    
    public byte[] dagID = new byte[16];

    /* This is from the DAO option - should allow multiple of these... */
    private int targetPrefixLen;
    private byte[] targetPrefix = new byte[16];

    public static final String RPL_NAMES[] = {"DIS", "DIO", "DAO", "DAO ACK"};

    public static final byte RPL_OPTION_PAD1 = 0;
    public static final byte RPL_OPTION_PADN = 1;
    public static final byte RPL_OPTION_TARGET = 5;
    public static final byte RPL_OPTION_TRANSIT = 6;
    
    public RPLPacket(int code) {
        super.type = ICMP6_TYPE_RPL;
        super.code = code;
    }
    
    public RPLPacket() {
    }

    public void parsePacketData(IPv6Packet packet) {
        super.parsePacketData(packet);
        /* Skip type, code and checksum  */
        packet.incPos(4);
        switch(code) {
        case RPL_DIS:
            break;
        case RPL_DIO:
            instanceID = packet.getData(0) & 0xff;
            version = packet.getData(1) & 0xff;
            rank = packet.get16(2) & 0xffff;
            
            flag = packet.getData(4) & 0xff;
            dtsn = packet.getData(5) & 0xff;

            /* two reserved */
            packet.incPos(8);
            
            /* copy DAG ID */
            packet.copy(0, dagID, 0, 16);
            break;
        case RPL_DAO:
            instanceID = packet.getData(0) & 0xff;
            flag = packet.getData(1) & 0xff;
            /* reserved 2 */
            sequence = packet.getData(3) & 0xff;

            packet.incPos(4);

 //           System.out.print("Parsing DAO");
            if ((flag & RPL_DAO_D_FLAG) > 0) {
                /* copy DAG ID */
                packet.copy(0, dagID, 0, 16);
                packet.incPos(16);
//                System.out.print(" DAG ID:");
//                IPv6Packet.printAddress(System.out, dagID);
            }
            
            /* Handle the options */
            while(packet.getPayloadLength() > 0) {
                boolean skipLen = false;
                switch (packet.getData(0)) {
                case RPL_OPTION_PAD1:
                    packet.incPos(1);
                    skipLen = true;
                    System.out.println("PAD 1");
                    break;
                case RPL_OPTION_TARGET:
                    /* will only handle one target for now... */
                    targetPrefixLen = packet.getData(3) & 0xff;
//                    System.out.print("Got TARGET option - prefixlen:" + targetPrefixLen);
                    packet.copy(4, targetPrefix, 0, (targetPrefixLen + 7) / 8);
                    break;
                case RPL_OPTION_TRANSIT:
                    lifetime = packet.getData(5);
 //                   System.out.print("Lifetime: " + lifetime);
                    break;
                default:
                }
                if (!skipLen) {
                    packet.incPos(2 + packet.getData(1) & 0xff);
                }
            }
 //           System.out.println();
            break;
        }
    }

    public RPLPacket createDIS() {
        RPLPacket p = new RPLPacket(RPL_DIS);
        return p;
    }
        
    public void printPacket(PrintStream out) {
        String name = "";
        if (code < RPL_NAMES.length) {
            name = RPL_NAMES[code];
        }
        out.print("ICMP6 - RPL " + name);
        switch (code) {
        case RPL_DIO:
            System.out.print(" Rank: " + (rank / 128.0));
            System.out.print(" DAG ID: ");
            IPv6Packet.printAddress(System.out, dagID);
            System.out.println();
            break;
        case RPL_DAO:
            System.out.print(" Seq: " + sequence + " Lifetime: " + lifetime + " Target:");
            IPv6Packet.printAddress(System.out, targetPrefix);
            break;
        }
    }
}
