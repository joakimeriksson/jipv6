/**
 * Copyright (c) 2009, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of jipv6.
 *
 * $Id: $
 *
 * -----------------------------------------------------------------
 *
 *
 * Author  : Joakim Eriksson
 * Created :  mar 2009
 * Updated : $Date:$
 *           $Revision:$
 */

package se.sics.jipv6.http;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Hashtable;
import java.util.Vector;

import se.sics.jipv6.core.IPStack;
import se.sics.jipv6.core.TCPConnection;
import se.sics.jipv6.core.TCPListener;
import se.sics.jipv6.core.TCPPacket;

public class HttpServer implements TCPListener, Runnable{

    private IPStack ipStack;
    private TCPConnection serverConnection;    
    private Hashtable<String, HttpServlet> servlets = new Hashtable<String, HttpServlet>();
    private Vector<TCPConnection> pending = new Vector<TCPConnection>();
    private String status = "";
    
    public HttpServer(IPStack stack) {
	ipStack = stack;
	serverConnection = ipStack.listen(80);
	serverConnection.setTCPListener(this);
	new Thread(this).start();
    }

    public void connectionClosed(TCPConnection connection) {
    }

    public void newConnection(TCPConnection connection) {
	handleConnection(connection);
    }

    public void tcpDataReceived(TCPConnection source, TCPPacket packet) {
    }
    
    public void registerServlet(String path, HttpServlet servlet) {
	servlets.put(path, servlet);
    }
    
    private synchronized void handleConnection(TCPConnection connection) {
	/* add and notify worker thread */
	System.out.println("%%% HttpServer: gotten new connection, adding to pending...");
	pending.addElement(connection);
	notify();
    }
    
    private void handlePendingConnections() {
	while(true) {
	    TCPConnection connection = null;
	    synchronized(this) {
		while(pending.size() == 0)
		    try {
			System.out.println("%%% HttpServer: worker waiting...");
			status = "waiting for connections";
			wait();
			/* take first and handle... */
			System.out.println("%%% HttpServer: worker notified...");
		    } catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		    }
		    status = "got connection";
		    connection = pending.firstElement();
		    pending.removeElementAt(0);
	    }
	    InputStream input = connection.getInputStream();
	    OutputStream output = connection.getOutputStream();
	    connection.setTimeout(5000);
	    try {
		/* read a line */
		System.out.println("%%% HttpServer: reading req line from: " + input);
		status = "reading request line";
		String reqLine = readLine(input);
		reqLine = reqLine.trim();
		if (!handleRequest(reqLine, input, output, connection)) {
		    output.write("HTTP/1.0 404 NOT FOUND\r\n\r\n".getBytes());
		}
	    } catch (Exception e) {
		e.printStackTrace();
	    } finally {
		try {
		    output.close();
		    input.close();
		} catch (IOException e) {
		}
		connection.close();
	    }
	}
    }

    private boolean handleRequest(String reqLine, InputStream input,
            OutputStream output, TCPConnection connection) throws IOException {
        int space = reqLine.indexOf(' ');
        if (space != -1) {
            String method = reqLine.substring(0, space);
            String path = reqLine.substring(space + 1, reqLine.lastIndexOf(' '));
            System.out.println("Method: " + method);
            System.out.println("Path: " + path);
            int query = reqLine.indexOf('?');
            if (query > 0) {
                path = path.substring(0, query);
            }
            status = "finding servlet: " + path;
            HttpServlet servlet = servlets.get(path);
            if (servlet != null) {
                // ignore headers for speed...			
                //			
                //		    String line = null;
                //		    while((line = readLine(input)) != null) {
                //			line = line.trim();
                //			System.out.println("/// HTTP Header: " + line);
                //			if (line.length() == 0) {
                //			    break;
                //			}
                //		    }
                HttpServletRequest req = new HttpServletRequest(connection, method, path);
                HttpServletResponse resp = new HttpServletResponse(connection);
                status = "Servicing servlet";
                servlet.service(req, resp);
                return true;
            }
        }
        return false;
    }
    
    public void run() {
	System.out.println("%%% HttpServer: worker thread started...");
	handlePendingConnections();
    }

    private String readLine(InputStream input) throws IOException {
	StringBuffer sb = new StringBuffer();
	int c;
	while(((c = input.read()) != -1)) {
	    if (c != '\r') sb.append((char) c);
	    if (c == '\n') return sb.toString();
	}
	return null;
    }
    
    public void printStatus(PrintStream out) {
        out.println("HttpServer status: " + status);
    }
}
