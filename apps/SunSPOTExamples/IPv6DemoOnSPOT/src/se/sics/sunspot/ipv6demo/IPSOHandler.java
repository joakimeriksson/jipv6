package se.sics.sunspot.ipv6demo;

import se.sics.jipv6.core.IPStack;
import se.sics.jipv6.core.IPv6Packet;
import se.sics.jipv6.core.UDPListener;
import se.sics.jipv6.core.UDPPacket;

public class IPSOHandler implements UDPListener {

    private IPStack ipStack;
    private IPv6Demo spot;
    
    IPSOHandler(IPStack stack, IPv6Demo spot) {
	ipStack = stack;
	this.spot = spot;
    }
    
    public void packetReceived(IPv6Packet packet, UDPPacket udp) {
	  String cmd = new String(udp.getPayload());
          int start = 0, end, len = cmd.length();
          StringBuffer reply = new StringBuffer();
	  System.out.println("Receive cmd: " + cmd);
          do {
            // Skip initial whitespace
            while (start < len && cmd.charAt(start) <= 32) start++;

            // Find end of command
            for(end = start + 1; end < len && cmd.charAt(end) > 32; end++);

            if (start < len && end > start) {
              // Handle command
              switch (cmd.charAt(start)) {
              case 'A':
                if (start + 1 < end) {
                  // Set leds
                  spot.ledsStatus = cmd.charAt(start + 1) == '0' ? 0 : 1;
                  spot.updateLeds();
                }
                reply.append('A').append(spot.ledsStatus);
                break;
              case 'T':
                try {
                  double t = spot.temperatureSensor.getCelsius();
                  reply.append('T').append((int)t).append('.').append((int) (t / 10));
                } catch (Exception e) {
                  e.printStackTrace();
                  reply.append((char)0xff).append('T');
                }
                break;
              case 'L':
                try {
                  double v = spot.lightSensor.getValue();
                  reply.append('L').append((int)v).append('.').append((int) (v / 10));
                } catch (Exception e) {
                  e.printStackTrace();
                  reply.append((char)0xff).append('L');
                }
                break;
              case 'H':
                reply.append("H0.0");
                break;
              default:
                reply.append((char)0xff).append(cmd.charAt(start));
                break;
              }
              reply.append("\r\n");
            }
            start = end + 1;
          } while(start < len);

          if (reply.length() > 0) {
            UDPPacket replyPacket = udp.replyPacket();
            replyPacket.setPayload(reply.toString().getBytes());
            IPv6Packet ipReply = packet.replyPacket(replyPacket);
            ipReply.setSourceAddress(ipStack.getIPAddress());
            ipStack.sendPacket(ipReply, null);
          }
    }
}