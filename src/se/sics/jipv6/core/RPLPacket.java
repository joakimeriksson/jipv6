package se.sics.jipv6.core;

public class RPLPacket extends ICMP6Packet {

    public static final int ICMP6_TYPE_RPL = 155;
    
    public static final int RPL_DIS = 0;
    public static final int RPL_DIO = 1;
    public static final int RPL_DAO = 2;
    public static final int RPL_DAO_ACK = 3;
    
    
    public RPLPacket(int code) {
        super.type = ICMP6_TYPE_RPL;
        super.code = code;
    }
    
    public RPLPacket createDIS() {
        RPLPacket p = new RPLPacket(RPL_DIS);
        
        return p;
    }
    
    
}
