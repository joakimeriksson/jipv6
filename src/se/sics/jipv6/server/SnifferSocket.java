package se.sics.jipv6.server;

import java.io.IOException;

import javax.websocket.ClientEndpoint;
import javax.websocket.CloseReason;
import javax.websocket.OnClose;
import javax.websocket.OnError;
import javax.websocket.OnMessage;
import javax.websocket.OnOpen;
import javax.websocket.Session;
import javax.websocket.server.ServerEndpoint;

@ClientEndpoint
@ServerEndpoint(value="/events/")
public class SnifferSocket
{
    
    Session session;
    @OnOpen
    public void onWebSocketConnect(Session sess)
    {
        this.session = sess;
        System.out.println("YYY: Socket Connected: " + sess);
    }
    
    @OnMessage
    public void onWebSocketText(String message)
    {
        System.out.println("YYY: Received TEXT message: " + message);
        try {
            session.getBasicRemote().sendText("Echo:" + message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
    @OnClose
    public void onWebSocketClose(CloseReason reason)
    {
        System.out.println("YYY: Socket Closed: " + reason);
    }
    
    @OnError
    public void onWebSocketError(Throwable cause)
    {
        cause.printStackTrace(System.err);
    }
}