package se.sics.jipv6.core;

public class HC06Packeter implements IPPacketer {

    public final static int SICSLOWPAN_UDP_PORT_MIN                     = 0xF0B0;
    public final static int SICSLOWPAN_UDP_PORT_MAX                     = 0xF0BF;   /* F0B0 + 15 */

    public final static int SICSLOWPAN_DISPATCH_IPV6                    = 0x41; /* 01000001 = 65 */
    public final static int SICSLOWPAN_DISPATCH_HC1                     = 0x42; /* 01000010 = 66 */
    public final static int SICSLOWPAN_DISPATCH_IPHC                    = 0x60; /* 011xxxxx = ... */
    public final static int SICSLOWPAN_DISPATCH_FRAG1                   = 0xc0; /* 1100= 0xxx */
    public final static int SICSLOWPAN_DISPATCH_FRAGN                   = 0xe0; /* 1110= 0xxx */

    /*
     * Values of fields within the IPHC encoding first byte
     * (C stands for compressed and I for inline)
     */
    public final static int SICSLOWPAN_IPHC_TC_C                        = 0x10;
    public final static int SICSLOWPAN_IPHC_FL_C                        = 0x08;
    public final static int SICSLOWPAN_IPHC_NH_C                        = 0x04;
    public final static int SICSLOWPAN_IPHC_TTL_1                       = 0x01;
    public final static int SICSLOWPAN_IPHC_TTL_64                      = 0x02;
    public final static int SICSLOWPAN_IPHC_TTL_255                     = 0x03;
    public final static int SICSLOWPAN_IPHC_TTL_I                       = 0x00;


    /* Values of fields within the IPHC encoding second byte */
    public final static int SICSLOWPAN_IPHC_CID                         = 0x80;

    public final static int SICSLOWPAN_IPHC_SAC                         = 0x40;
    public final static int SICSLOWPAN_IPHC_SAM_00                      = 0x00;
    public final static int SICSLOWPAN_IPHC_SAM_01                      = 0x10;
    public final static int SICSLOWPAN_IPHC_SAM_10                      = 0x20;
    public final static int SICSLOWPAN_IPHC_SAM_11                      = 0x30;

    public final static int SICSLOWPAN_IPHC_M                           = 0x08;
    public final static int SICSLOWPAN_IPHC_DAC                         = 0x04;
    public final static int SICSLOWPAN_IPHC_DAM_00                      = 0x00;
    public final static int SICSLOWPAN_IPHC_DAM_01                      = 0x01;
    public final static int SICSLOWPAN_IPHC_DAM_10                      = 0x02;
    public final static int SICSLOWPAN_IPHC_DAM_11                      = 0x03;

    private static final int SICSLOWPAN_NHC_UDP_MASK                    = 0xf8;
    private static final int SICSLOWPAN_NHC_UDP_ID                      = 0xf0;
    private static final int SICSLOWPAN_NHC_UDP_CS_P00  =                 0xf0;
    private static final int SICSLOWPAN_NHC_UDP_CS_P01 =                  0xf1;
    private static final int SICSLOWPAN_NHC_UDP_CS_P10 =                  0xf2;
    private static final int SICSLOWPAN_NHC_UDP_CS_P11 =                  0xf3;
    private static final int SICSLOWPAN_NHC_UDP_CHECKSUM_COMPR =          0x04;

    public final static int PROTO_UDP = 17;
    public final static int PROTO_TCP = 6;
    public final static int PROTO_ICMP = 58;

    private static final boolean DEBUG = false;

    private LoWPANFragmenter fragmenter = new LoWPANFragmenter();
        
    /**
     * \brief check whether we can compress the IID in
     * address to 16 bits.
     * This is used for unicast addresses only, and is true
     * if first 49 bits of IID are 0
     * @return 
     */
    private boolean is16bitCompressable(byte[] address) {
      return ((address[8] | address[9] | address[10] | address[11] |
          address[12] | address[13]) == 0) &&
          (address[14] & 0x80) == 0;
    }

    /* FFXX::00XX:XXXX:XXXX */
    private boolean isMcastAddrCompressable48(byte[] a) {
        for(int i = 2; i < 11; i++) {
            if (a[i] != 0) return false;
        }
        return true;
    }

    /* FFXX::00XX:XXXX */
    private boolean isMcastAddrCompressable32(byte[] a) {
        for(int i = 2; i < 13; i++) {
            if (a[i] != 0) return false;
        }
        return true;
    }
    
    /* FF02::00XX */
    private boolean isMcastAddrCompressable8(byte[] a) {
        if (a[1] != 0x02) return false;
        for(int i = 2; i < 15; i++) {
            if (a[i] != 0) return false;
        }
        return true;
    }
    
    
    /* ripped from HC01 */
    private static class AddrContext {
        byte[] prefix = new byte[16];

        public AddrContext(long a1,long a2,long a3,long a4) {
            for(int i = 0; i < 4; i++) {
                prefix[3 - i] = (byte)(a1 & 0xff);
                a1 = a1 >> 8;
                prefix[4 + 3 - i] = (byte)(a2 & 0xff);
                a2 = a2 >> 8;
                prefix[8 + 3 - i] = (byte)(a3 & 0xff);
                a3 = a3 >> 8;
                prefix[12 + 3 - i] = (byte)(a4 & 0xff);
                a4 = a4 >> 8;
            }
        }

        public boolean matchPrefix(byte[] address) {
            for (int i = 0; i < prefix.length; i++) {
                if (prefix[i] != address[i])
                    return false;
            }
            return true;
        }
    }

    /* HC06 specifies 16 contexts */
    private AddrContext[] contexts = new AddrContext[16];

    public void setContext(int cIndex, long a1, long a2, long a3, long a4) {
        contexts[cIndex] = new AddrContext(a1, a2, a3, a4);
    }
    
    
    private int lookupContext(byte[] address) {
        for (int i = 0; i < contexts.length; i++) {
            if (contexts[i] != null && contexts[i].matchPrefix(address)) {
                return i;
            }
        }
        return -1;
    }

    public byte[] generatePacketData(IPv6Packet packet) {
        byte[] data = new byte[40 + 8];
        int hc06_ptr = 2;

        data[0] = SICSLOWPAN_DISPATCH_IPHC;
        data[1] = 0;
        data[2] = 0; /* might not be used - but needs to be cleared */

        /* check if dest context exists (for allocating third byte) */
        /* TODO: fix this so that it remembers the looked up values for
           avoiding two lookups - or set the lookup values immediately */
        if(lookupContext(packet.destAddress) != -1 ||
                lookupContext(packet.sourceAddress) != -1) {
            /* set context flag and increase hc06_ptr */
            if (DEBUG) System.out.println("IPHC: compressing dest or src ipaddr - setting CID\n");
            data[1] |= SICSLOWPAN_IPHC_CID;
            hc06_ptr++;
        }

        /*
         * Traffic class, flow label
         * If flow label is 0, compress it. If traffic class is 0, compress it
         * We have to process both in the same time as the offset of traffic class
         * depends on the presence of version and flow label
         */

        /* hc06 format of tc is ECN | DSCP , original is DSCP | ECN */
        int tmp = (packet.trafficClass << 6) & 0xff | (packet.trafficClass >> 2);

        if(packet.flowLabel == 0) {
            /* flow label can be compressed */
            data[0] |= SICSLOWPAN_IPHC_FL_C;
            if(packet.trafficClass == 0) {
                /* compress (elide) all */
                data[0] |= SICSLOWPAN_IPHC_TC_C;
            } else {
                /* compress only the flow label */
                data[hc06_ptr] = (byte) (tmp & 0xff);
                hc06_ptr += 1;
            }
        } else {
            /* Flow label cannot be compressed - maybe check traffic class 0x3f */
            if((packet.trafficClass & 0x03) == 0) {
                /* compress only traffic class */
                data[0] |= SICSLOWPAN_IPHC_TC_C;
                data[hc06_ptr] = (byte) ((tmp & 0xc0) | (packet.flowLabel >> 16) & 0x0f);
                data[hc06_ptr + 1] = (byte) ((packet.flowLabel >> 8) & 0xff);
                data[hc06_ptr + 2] = (byte) (packet.flowLabel & 0xff);
                hc06_ptr += 3;
            } else {
                /* compress nothing */
                data[hc06_ptr] = (byte) tmp;
                /* but replace the top byte with the new ECN | DSCP format*/
                data[hc06_ptr + 1] = (byte) ((packet.flowLabel >> 16) & 0x0f);
                data[hc06_ptr + 2] = (byte) ((packet.flowLabel >> 8) & 0xff);
                data[hc06_ptr + 3] = (byte) (packet.flowLabel & 0xff);
                hc06_ptr += 4;
            }
        }

        /* Next header compression */
        if(packet.nextHeader == PROTO_UDP) {
            data[0] |= SICSLOWPAN_IPHC_NH_C;
        } else {
            data[hc06_ptr] = packet.nextHeader;
            hc06_ptr += 1;
        }
        
        /*
         * Hop limit
         * if 1: compress, encoding is 01
         * if 64: compress, encoding is 10
         * if 255: compress, encoding is 11
         * else do not compress
         */
        switch(packet.hopLimit) {
          case 1:
            data[0] |= SICSLOWPAN_IPHC_TTL_1;
            break;
          case 64:
            data[0] |= SICSLOWPAN_IPHC_TTL_64;
            break;
          case 255:
            data[0] |= SICSLOWPAN_IPHC_TTL_255;
            break;
          default:
            data[hc06_ptr] = (byte) packet.hopLimit;
            hc06_ptr += 1;
            break;
        }

        int context = 0;
        /* source address - cannot be multicast */
        if(packet.isSourceUnspecified()) {
            System.out.println("IPHC: compressing unspecified - setting SAC\n");
            data[1] |= SICSLOWPAN_IPHC_SAC;
            data[1] |= SICSLOWPAN_IPHC_SAM_00;
        } else if((context = lookupContext(packet.sourceAddress)) != -1) {
            /* elide the prefix - indicate by CID and set context + SAC */
            System.out.println("IPHC: compressing src with context - setting CID & SAC ctx: " +
                    context);
            data[1] |= SICSLOWPAN_IPHC_CID | SICSLOWPAN_IPHC_SAC;
            data[2] |= context << 4;
            /* compession compare with this nodes address (source) */
            if(packet.isSourceMACBased()){
                /* elide the IID */
                data[1] |= SICSLOWPAN_IPHC_SAM_11; /* 0-bits */
          } else {
            if(is16bitCompressable(packet.sourceAddress)){
              /* compress IID to 16 bits */
                data[1] |= SICSLOWPAN_IPHC_SAM_10; /* 16-bits */
                data[hc06_ptr++] = packet.sourceAddress[14];
                data[hc06_ptr++] = packet.sourceAddress[15];
            } else {
              /* do not compress IID */
              data[1] |= SICSLOWPAN_IPHC_SAM_01; /* 64-bits */
              System.arraycopy(packet.sourceAddress, 8, data, hc06_ptr, 8);
              hc06_ptr += 8;
            }
          }
            /* No context found for this address */
        } else if(IPStack.isLinkLocal(packet.sourceAddress)) {
            // TODO: make a function of this: compress_ll_hc06(&UIP_IP_BUF->srcipaddr);
            if(packet.isSourceMACBased()){
                data[1] |= SICSLOWPAN_IPHC_SAM_11; /* 0-bits */
            } else if(is16bitCompressable(packet.sourceAddress)){
                /* compress IID to 16 bits fe80::XXXX */
                data[1] |= SICSLOWPAN_IPHC_SAM_10; /* 16-bits */
                data[hc06_ptr++] = packet.sourceAddress[14];
                data[hc06_ptr++] = packet.sourceAddress[15];
                hc06_ptr += 2;
            } else {
                /* do not compress IID => fe80::IID */
                data[1] |= SICSLOWPAN_IPHC_SAM_01; /* 64-bits */
                System.arraycopy(packet.sourceAddress, 8, data, hc06_ptr, 8);
                hc06_ptr += 8;
            }
        } else {
            /* send the full address => SAC = 0, SAM = 00 */
            data[1] |= SICSLOWPAN_IPHC_SAM_00; /* 128-bits */
            System.arraycopy(packet.sourceAddress, 0, data, hc06_ptr, 16);
            hc06_ptr += 16;
        }

        /* dest address*/
        if(packet.isMulticastDestination()) {
            /* Address is multicast, try to compress */
            data[1] |= SICSLOWPAN_IPHC_M;
            if(isMcastAddrCompressable8(packet.destAddress)) {
                data[1] |= SICSLOWPAN_IPHC_DAM_11;
                /* use last byte */
                data[hc06_ptr++] = packet.destAddress[15];
            } else if(isMcastAddrCompressable32(packet.destAddress)){
                data[1] |= SICSLOWPAN_IPHC_DAM_10;
                /* second byte + the last three */
                data[hc06_ptr] = packet.destAddress[1];
                System.arraycopy(packet.destAddress, 13, data, hc06_ptr + 1, 3);
                hc06_ptr += 4;
            } else if(isMcastAddrCompressable48(packet.destAddress)){
                data[1] |= SICSLOWPAN_IPHC_DAM_01;
            /* second byte + the last five */
                data[hc06_ptr] = packet.destAddress[1];
                System.arraycopy(packet.destAddress, 11, data, hc06_ptr + 1, 5);
                hc06_ptr += 6;
            } else {
                data[1] |= SICSLOWPAN_IPHC_DAM_00;
                /* full address */
                System.arraycopy(packet.destAddress, 0, data, hc06_ptr + 1, 16);
                hc06_ptr += 16;
            }
        } else {
            /* Address is unicast, try to compress */
            if((context = lookupContext(packet.destAddress)) != -1) {
                /* elide the prefix */
                data[1] |= SICSLOWPAN_IPHC_DAC;
                data[2] |= context;
                /* compession compare with link adress (destination) */
                if(packet.isDestinationMACBased()) {
                    /* elide the IID */
                    data[1] |= SICSLOWPAN_IPHC_DAM_11; /* 0-bits */
                } else {
                    if(is16bitCompressable(packet.destAddress)) {
                        /* compress IID to 16 bits */
                        data[1] |= SICSLOWPAN_IPHC_DAM_10; /* 16-bits */
                        data[hc06_ptr++] = packet.destAddress[14];
                        data[hc06_ptr++] = packet.destAddress[15];
                    } else {
                      /* do not compress IID */
                      data[1] |= SICSLOWPAN_IPHC_DAM_01; /* 64-bits */
                      System.arraycopy(packet.destAddress, 8, data, hc06_ptr, 8);
                      hc06_ptr += 8;
                    }
                }
                /* No context found for this address */
            } else if(IPStack.isLinkLocal(packet.destAddress)) {
                // TODO: make a function of this: compress_ll_hc06(&UIP_IP_BUF->destipaddr);
                if(packet.isDestinationMACBased()) {
                    data[1] |= SICSLOWPAN_IPHC_DAM_11; /* 0-bits */
                } else if(is16bitCompressable(packet.destAddress)){
                    /* compress IID to 16 bits fe80::XXXX */
                    data[1] |= SICSLOWPAN_IPHC_DAM_10; /* 16-bits */
                    data[hc06_ptr++] = packet.destAddress[14];
                    data[hc06_ptr++] = packet.destAddress[15];
                } else {
                    /* do not compress IID => fe80::IID */
                    data[1] |= SICSLOWPAN_IPHC_DAM_01; /* 64-bits */
                    System.arraycopy(packet.destAddress, 8, data, hc06_ptr, 8);
                    hc06_ptr += 8;
                }
            } else {
                /* send the full address */
                data[1] |= SICSLOWPAN_IPHC_DAM_00; /* 128-bits */
                System.arraycopy(packet.destAddress, 0, data, hc06_ptr, 16);
                hc06_ptr += 16;
            }
        }

        /* UDP header compression */
        if(packet.nextHeader == UDPPacket.DISPATCH) {
          UDPPacket udp = (UDPPacket) packet.getIPPayload();
          if( udp.sourcePort  >= SICSLOWPAN_UDP_PORT_MIN &&
              udp.sourcePort <  SICSLOWPAN_UDP_PORT_MAX &&
              udp.destinationPort >= SICSLOWPAN_UDP_PORT_MIN &&
              udp.destinationPort <  SICSLOWPAN_UDP_PORT_MAX) {
            /* we can compress. Copy compressed ports, full chcksum */
            data[hc06_ptr++] = (byte) (((udp.sourcePort - SICSLOWPAN_UDP_PORT_MIN) << 4) +
                (udp.destinationPort - SICSLOWPAN_UDP_PORT_MIN));
            int checksum = udp.doVirtualChecksum(packet);
            data[hc06_ptr++] = (byte) (checksum >> 8);
            data[hc06_ptr++] = (byte) (checksum & 0xff);
          } else {
            /* we cannot compress. Copy uncompressed ports, full chcksum */
            data[hc06_ptr++] = (byte) (udp.sourcePort >> 8);
            data[hc06_ptr++] = (byte) (udp.sourcePort & 0xff);
            data[hc06_ptr++] = (byte) (udp.destinationPort >> 8);
            data[hc06_ptr++] = (byte) (udp.destinationPort & 0xff);
            int checksum = udp.doVirtualChecksum(packet);
            data[hc06_ptr++] = (byte) (checksum >> 8);
            data[hc06_ptr++] = (byte) (checksum & 0xff);
          }
        }

        
        if (DEBUG) System.out.println("HC06 Header compression: size " + hc06_ptr);
        if (DEBUG) {
            System.out.print("HC06: From ");
            IPv6Packet.printAddress(System.out, packet.sourceAddress);
            System.out.print(" to ");
            IPv6Packet.printAddress(System.out, packet.destAddress);
            System.out.println();
        }
        byte[] pload;
        if (packet.nextHeader == UDPPacket.DISPATCH) {
            UDPPacket udp = (UDPPacket) packet.getIPPayload();
            /* already have the udp header */
            pload = udp.payload;
        } else {
            IPPayload payload = packet.getIPPayload();
            pload = payload.generatePacketData(packet);
        }
        if (DEBUG) System.out.println("HC06 Payload size: " + pload.length);

        byte[] dataPacket = new byte[hc06_ptr + pload.length];
        System.arraycopy(data, 0, dataPacket, 0, hc06_ptr);
        System.arraycopy(pload, 0, dataPacket, hc06_ptr, pload.length);
        return dataPacket;
    }

    public byte getDispatch() {
        return 0;
    }

    public boolean parsePacketData(IPv6Packet packet) {
        int headerSize = 0;
        int compressedHeaderSize = 0;
        if ((packet.getData(0) & 0xf8) == SICSLOWPAN_DISPATCH_FRAG1) {
            /* first fragment need to decompress first to get "size" diff. */
            packet.incPos(4);
            int pos = packet.currentPos;
            headerSize = decompress(packet);
            compressedHeaderSize = packet.currentPos - pos;
            packet.currentPos = pos - 4;
        }
                
        if (!fragmenter.handleFragment(packet, headerSize, compressedHeaderSize)) {
            /* fragment - and not a complete packet */
            return false;
        }
        
        return decompress(packet) != 0;
    }
    
   public int decompress(IPv6Packet packet) {       
        int headerSize = 40;
        
        /* Handle "uncompression" */
        int cid = (packet.getData(1) >> 7) & 0x01;
        int sci = 0;
        int dci = 0;

        if (cid == 1) {
            sci = packet.getData(2) >> 4;
            dci = packet.getData(2) & 0x0f;
        }

        int hc06_ptr = 2 + cid;

        packet.version = 6;
        UDPPacket udp = null;

        int checkSum = 0;
        int srcPort = 0;
        int destPort = 0;

        /* Traffic class and flow label */
        if((packet.getData(0) & SICSLOWPAN_IPHC_FL_C) == 0) {
            /* Flow label are carried inline */
            if((packet.getData(0) & SICSLOWPAN_IPHC_TC_C) == 0) {
                /* Traffic class is carried inline */
                packet.flowLabel = packet.get24(hc06_ptr + 1);
                int tmp = packet.getData(hc06_ptr);
                hc06_ptr += 4;
                /* hc06 format of tc is ECN | DSCP , original is DSCP | ECN */
                packet.trafficClass = ((tmp >> 2) & 0x3f) | (tmp << 6) & (0x80 + 0x40);
                /* ECN rolled down two steps + lowest DSCP bits at top two bits */
            } else {
                /* highest flow label bits + ECN bits */
                int tmp = packet.getData(hc06_ptr);
                packet.trafficClass = (tmp >> 6) & 0x0f; 
                packet.flowLabel = packet.get16(hc06_ptr + 1);
                hc06_ptr += 3;
            }
        } else {
            /* Version is always 6! */
            /* Version and flow label are compressed */
            if((packet.getData(0) & SICSLOWPAN_IPHC_TC_C) == 0) {
                /* Traffic class is inline */
                packet.trafficClass =((packet.getData(hc06_ptr) >> 6) & 0x03);
                packet.trafficClass = (packet.getData(hc06_ptr) << 2);
                hc06_ptr += 1;
            }
        }

        /* Next Header */
        if((packet.getData(0) & SICSLOWPAN_IPHC_NH_C) == 0) {
            /* Next header is carried inline */
            packet.nextHeader = packet.getData(hc06_ptr);
            hc06_ptr += 1;
        } else {
            if (DEBUG) System.out.println("Next header compressed!");
        }

        /* Hop limit */
        switch(packet.getData(0) & 0x03) {
        case SICSLOWPAN_IPHC_TTL_1:
            packet.hopLimit = 1;
            break;
        case SICSLOWPAN_IPHC_TTL_64:
            packet.hopLimit = 64;
            break;
        case SICSLOWPAN_IPHC_TTL_255:
            packet.hopLimit = 255;
            break;
        case SICSLOWPAN_IPHC_TTL_I:
            packet.hopLimit = packet.getData(hc06_ptr);
            hc06_ptr += 1;
            break;
        }

        /* context based compression */
        if((packet.getData(1) & SICSLOWPAN_IPHC_SAC) > 0) {
            /* Source address */
            AddrContext context = null;
            if((packet.getData(1) & SICSLOWPAN_IPHC_SAM_11) != SICSLOWPAN_IPHC_SAM_00) {
                if (DEBUG) System.out.println("Setting context:" + sci + " SAM:" + (packet.getData(1) & SICSLOWPAN_IPHC_SAM_11));
                context = contexts[sci];
            }

            switch(packet.getData(1) & SICSLOWPAN_IPHC_SAM_11) {
            case SICSLOWPAN_IPHC_SAM_00:
                /* copy the unspecificed address */
                packet.sourceAddress = IPStack.UNSPECIFIED;
                break;
            case SICSLOWPAN_IPHC_SAM_01: /* 64 bits */
                /* copy prefix from context */
                System.arraycopy(context.prefix, 0, packet.sourceAddress, 0, 8);
                /* copy IID from packet */
                packet.copy(hc06_ptr, packet.sourceAddress, 8, 8);
                hc06_ptr += 8;
                break;
            case SICSLOWPAN_IPHC_SAM_10: /* 16 bits */
                /* unicast address */
                System.arraycopy(context.prefix, 0, packet.sourceAddress, 0, 8);
                /* copy 6 NULL bytes then 2 last bytes of IID */
                packet.copy(hc06_ptr, packet.sourceAddress, 14, 2);
                hc06_ptr += 2;
                break;
            case SICSLOWPAN_IPHC_SAM_11: /* 0-bits */
                /* copy prefix from context */
                System.arraycopy(context.prefix, 0, packet.sourceAddress, 0, 8);
                /* infer IID from L2 address */
                byte[] llsender = packet.getLinkSource(); 
                System.arraycopy(llsender, 0, packet.sourceAddress, 
                        16 - llsender.length, llsender.length);
                packet.sourceAddress[8] ^= 0x02;
                break;
            }
            /* end context based compression */
        } else {
            /* no compression and link local */
            switch(packet.getData(1) & SICSLOWPAN_IPHC_SAM_11) {
            case SICSLOWPAN_IPHC_SAM_00: /* 128 bits */
                /* copy whole address from packet */
                packet.copy(hc06_ptr, packet.sourceAddress, 0, 16);
                hc06_ptr += 16;
                break;
            case SICSLOWPAN_IPHC_SAM_01: /* 64 bits */
                packet.sourceAddress[0] = (byte) 0xfe;
                packet.sourceAddress[1] = (byte) 0x80;
                /* copy IID from packet */
                packet.copy(hc06_ptr, packet.sourceAddress, 8, 8);
                hc06_ptr += 8;
                break;
            case SICSLOWPAN_IPHC_SAM_10: /* 16 bits */
                packet.sourceAddress[0] = (byte) 0xfe;
                packet.sourceAddress[1] = (byte) 0x80;
                packet.copy(hc06_ptr, packet.sourceAddress, 14, 2);
                hc06_ptr += 2;
                break;
            case SICSLOWPAN_IPHC_SAM_11: /* 0 bits */
                /* setup link-local address */
                packet.sourceAddress[0] = (byte) 0xfe;
                packet.sourceAddress[1] = (byte) 0x80;
                /* infer IID from L2 address */
                byte[] llsender = packet.getLinkSource();
                System.arraycopy(llsender, 0, packet.sourceAddress, 
                        16 - llsender.length, llsender.length);
                packet.sourceAddress[8] ^= 0x02;
                break;
            }
        }

        /* Destination address */

        /* multicast compression */
        if((packet.getData(1) & SICSLOWPAN_IPHC_M) != 0) {
            /* context based multicast compression */
            if((packet.getData(1) & SICSLOWPAN_IPHC_DAC) != 0) {
                /* TODO: implement this */
            } else {
                /* non-context based multicast compression */
                switch (packet.getData(1) & SICSLOWPAN_IPHC_DAM_11) {
                case SICSLOWPAN_IPHC_DAM_00: /* 128 bits */
                    /* copy whole address from packet */
                    packet.copy(hc06_ptr, packet.destAddress, 0, 16);
                    hc06_ptr += 16;
                    break;
                case SICSLOWPAN_IPHC_DAM_01: /* 48 bits FFXX::00XX:XXXX:XXXX */
                    packet.destAddress[0] = (byte) 0xff;
                    packet.destAddress[1] = packet.getData(hc06_ptr);
                    packet.copy(hc06_ptr + 1, packet.destAddress, 11, 5);
                    hc06_ptr += 6;
                    break;
                case SICSLOWPAN_IPHC_DAM_10: /* 32 bits FFXX::00XX:XXXX */
                    packet.destAddress[0] = (byte) 0xff;
                    packet.destAddress[1] = packet.getData(hc06_ptr);
                    packet.copy(hc06_ptr + 1, packet.destAddress, 13, 3);
                    hc06_ptr += 4;
                    break;
                case SICSLOWPAN_IPHC_DAM_11: /* 8 bits FF02::00XX */
                    packet.destAddress[0] = (byte) 0xff;
                    packet.destAddress[1] = (byte) 0x02;
                    packet.destAddress[15] = packet.getData(hc06_ptr);
                    hc06_ptr++;
                    break;
                }
            }
        } else {
            /* no multicast */
            /* Context based */
            if((packet.getData(1) & SICSLOWPAN_IPHC_DAC) != 0) {
                AddrContext context = contexts[dci];

                switch (packet.getData(1) & SICSLOWPAN_IPHC_DAM_11) {
                case SICSLOWPAN_IPHC_DAM_01: /* 64 bits */
                    System.arraycopy(context.prefix, 0, packet.destAddress, 0, 8);
                    /* copy IID from packet */
                    packet.copy(hc06_ptr, packet.destAddress, 8, 8);
                    hc06_ptr += 8;
                    break;
                case SICSLOWPAN_IPHC_DAM_10: /* 16 bits */
                    /* unicast address */
                    System.arraycopy(context.prefix, 0, packet.destAddress, 0, 8);
                    /* copy IID from packet */
                    packet.copy(hc06_ptr, packet.destAddress, 14, 2);
                    hc06_ptr += 2;
                    break;
                case SICSLOWPAN_IPHC_DAM_11: /* 0 bits */
                    /* unicast address */
                    System.arraycopy(context.prefix, 0, packet.destAddress, 0, 8);
                    /* infer IID from L2 address */
                    byte[] llreceiver = packet.getLinkDestination();
                    System.arraycopy(llreceiver, 0, packet.destAddress, 
                            16 - llreceiver.length, llreceiver.length);
                    packet.destAddress[8] ^= 0x02;
                    break;
                }      
            } else {
                /* not context based => link local M = 0, DAC = 0 - same as SAC */
                switch (packet.getData(1) & SICSLOWPAN_IPHC_DAM_11) {
                case SICSLOWPAN_IPHC_DAM_00: /* 128 bits */
                    packet.copy(hc06_ptr, packet.destAddress, 0, 16);
                    hc06_ptr += 16;
                    break;
                case SICSLOWPAN_IPHC_DAM_01: /* 64 bits */
                    packet.destAddress[0] = (byte) 0xfe;
                    packet.destAddress[1] = (byte) 0x80;
                    packet.copy(hc06_ptr, packet.destAddress, 8, 8);
                    hc06_ptr += 8;
                    break;
                case SICSLOWPAN_IPHC_DAM_10: /* 16 bits */
                    packet.destAddress[0] = (byte) 0xfe;
                    packet.destAddress[1] = (byte) 0x80;
                    packet.copy(hc06_ptr, packet.destAddress, 14, 2);
                    hc06_ptr += 2;
                    break;
                case SICSLOWPAN_IPHC_DAM_11: /* 0 bits */
                    packet.destAddress[0] = (byte) 0xfe;
                    packet.destAddress[1] = (byte) 0x80;
                    byte[] llreceiver = packet.getLinkDestination();
                    System.arraycopy(llreceiver, 0, packet.destAddress, 
                            16 - llreceiver.length, llreceiver.length);
                    packet.destAddress[8] ^= 0x02;
                    break;
                }
            }
        }
        
        /* Next header processing - continued */
        if((packet.getData(0) & SICSLOWPAN_IPHC_NH_C) != 0) {
            /* TODO: check if this is correct in hc-06 */
            /* The next header is compressed, NHC is following */
            if((packet.getData(hc06_ptr) & SICSLOWPAN_NHC_UDP_MASK) == SICSLOWPAN_NHC_UDP_ID) {
                packet.nextHeader = PROTO_UDP;
                boolean checksumCompressed = (packet.getData(hc06_ptr) & SICSLOWPAN_NHC_UDP_CHECKSUM_COMPR) != 0;
                switch(packet.getData(hc06_ptr) & SICSLOWPAN_NHC_UDP_CS_P11) {
                case SICSLOWPAN_NHC_UDP_CS_P00:
                    /* 1 byte for NHC, 4 byte for ports */
                    srcPort = packet.get16(hc06_ptr + 1);
                    destPort = packet.get16(hc06_ptr + 3);
                    hc06_ptr += 5;
                break;
/* TODO: ADD P01 / P10 also!!!! */
                case SICSLOWPAN_NHC_UDP_CS_P11:
                    /* 1 byte for NHC, 1 byte for ports */
                    srcPort = SICSLOWPAN_UDP_PORT_MIN + (packet.getData(hc06_ptr + 1) >> 4);
                    destPort = SICSLOWPAN_UDP_PORT_MIN + (packet.getData(hc06_ptr + 1) & 0x0F);
                    hc06_ptr += 2;
                    break;                    
                default:
                    System.out.println("sicslowpan uncompress_hdr: error unsupported UDP compression\n");
                }
                if (!checksumCompressed) {
                    checkSum = ((packet.getData(hc06_ptr) & 0xff) << 8) +
                            (packet.getData(hc06_ptr + 1) & 0xff);
                    hc06_ptr += 2;
                }

                udp = new UDPPacket();
                udp.sourcePort = srcPort;
                udp.destinationPort = destPort;
                udp.checkSum = checkSum;
                headerSize += 8;
            } else {
                System.out.printf("Unsupported next header compression:%02x\n",(packet.getData(hc06_ptr) & 0xFC));
            }
        }

        //        /* IP length field. */
        //        if(ip_len == 0) {
        //            /* This is not a fragmented packet */
        //            SICSLOWPAN_IP_BUF->len[0] = 0;
        //            SICSLOWPAN_IP_BUF->len[1] = packetbuf_datalen() - rime_hdr_len + uncomp_hdr_len - UIP_IPH_LEN;
        //        } else {
        //            /* This is a 1st fragment */
        //            SICSLOWPAN_IP_BUF->len[0] = (ip_len - UIP_IPH_LEN) >> 8;
        //            SICSLOWPAN_IP_BUF->len[1] = (ip_len - UIP_IPH_LEN) & 0x00FF;
        //        }

        //        /* length field in UDP header */
        //        if(SICSLOWPAN_IP_BUF->proto == UIP_PROTO_UDP) {
        //            memcpy(&SICSLOWPAN_UDP_BUF->udplen, ipBuf + len[0], 2);
        //        }

        if (DEBUG) {
            System.out.println("IPv6 / IPHC packet received NH:" + packet.nextHeader);
            System.out.println("TTL: " + (packet.hopLimit & 0xff));
            System.out.print("Src Addr: ");
            IPv6Packet.printAddress(System.out, packet.sourceAddress);
            System.out.println();
            System.out.print("Dst Addr: ");
            IPv6Packet.printAddress(System.out, packet.destAddress);
            System.out.println();
        }
        
        packet.incPos(hc06_ptr);
        
        if (udp != null) {
            /* if we have a udp payload we already have the udp headers in place */
            /* the rest is only the payload */
            udp.payload = packet.getPayload();
            udp.length = udp.payload.length + 8;
            /* add 8 to the payload length of the UDP packet */
            packet.payloadLen += 8;
            udp.doVirtualChecksum(packet);
            packet.setIPPayload(udp);
        }
        return headerSize;
    }
}
