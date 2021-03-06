/*
 * Copyright (c) 2016, SICS Swedish ICT.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
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
 * \author
 *      Joakim Eriksson <joakime@sics.se> & Niclas Finne <nfi@sics.se>
 *
 */
package se.sics.jipv6.server;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.Formatter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.websocket.server.ServerContainer;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.ContextHandlerCollection;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.websocket.jsr356.server.deploy.WebSocketServerContainerInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.sics.jipv6.analyzer.ExampleAnalyzer;
import se.sics.jipv6.analyzer.JShark;
import se.sics.jipv6.analyzer.NodeTable;
import se.sics.jipv6.analyzer.RPLAnalyzer;

public class SnifferServer extends AbstractHandler {

    private static final Logger log = LoggerFactory.getLogger(SnifferServer.class);

    private Server server;
    private ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private PrintStream out;
    private JShark sniffer;
    private boolean isRunning = false;

    private SnifferServer() {
        out = new PrintStream(baos);
    }

    public void setSniffer(JShark sniffer) {
        this.sniffer = sniffer;
    }
    
    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        JShark sniffer = this.sniffer;
        if (sniffer == null) {
            response.setContentType("text/plain;charset=utf-8");
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

            PrintWriter responseWriter = response.getWriter();
            try {
                responseWriter.print("No analyzer registered!");
                return;
            } finally {
                responseWriter.close();
            }
        }

        response.setContentType("text/html; charset=utf-8");
        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().println("<html><head><script type=\"text/javascript\" src=\"/www/vis.min.js\"></script>");
        response.getWriter().println("<script type=\"text/javascript\" src='/www/jquery-1.11.2.min.js'></script>");
        response.getWriter().println("<link href=\"/www/vis.min.css\" rel=\"stylesheet\" type=\"text/css\" />");
        response.getWriter().println("<link href=\"/www/colors.css\" rel=\"stylesheet\" type=\"text/css\" />");
        response.getWriter().println("</style>");

        response.getWriter().println("</head><body><h1>Super duper sniff server!</h1>");
        NodeTable nodeTable = sniffer.getNodeTable();
        response.getWriter().println("Number of nodes:" + nodeTable.nodeCount());
        response.getWriter().println("<h4>Node Table</h4>");
        response.getWriter().println("<pre>");
        nodeTable.print(new PrintWriter(response.getWriter()));
        response.getWriter().println("</pre>");
        response.getWriter().println("<br>Log:" + baos.size() + "<br><pre>" + baos.toString());
        response.getWriter().println("</pre><br>");
        response.getWriter().println("Topology:<pre>" + RPLAnalyzer.getRPLTopology(nodeTable) + "</pre>");
        response.getWriter().println("<script type=\"text/javascript\">\n");
        response.getWriter().println(RPLAnalyzer.getRPLTopology(nodeTable));
        response.getWriter().println("var data = { nodes: nodes, edges: edges };");
        response.getWriter().println("var options = {stack: false,margin: {item: 10,axis: 5}};");
        response.getWriter().println("var network;");
        response.getWriter().println("$(document).ready( function() {");
        response.getWriter().println("var container = document.getElementById('network-visualization');");
        response.getWriter().println("container.innerHTML = \"\";");
        response.getWriter().println("network = new vis.Network(container, data, options);");
        response.getWriter().println("container = document.getElementById('timeline-visualization');");
        response.getWriter().println(sniffer.getPacketStore().getJSPackets());
        response.getWriter().println("var gset = new vis.DataSet(groups);");
        response.getWriter().println("var iset = new vis.DataSet(items);");
        response.getWriter().println("var timeline = new vis.Timeline(container, null, options);");
        response.getWriter().println("timeline.setGroups(gset);");
        response.getWriter().println("timeline.setItems(iset);");
        response.getWriter().println("});");
        response.getWriter().println("</script><h4>Network Topology</h4><div id=\"network-visualization\"></div>");
        response.getWriter().println("<h4>Timeline</h4><div id=\"timeline-visualization\"><div></body></html>");
        baos.reset();
        baseRequest.setHandled(true);
    }

    public boolean isRunning() {
        return isRunning;
    }

    public void startWS() {
        if (isRunning) {
            return;
        }
        isRunning = true;
        Runnable r = new Runnable() {
            public void run() {
                server = new Server(8080);

                ResourceHandler resourceHandler = new ResourceHandler();
                resourceHandler.setDirectoriesListed(true);
                resourceHandler.setResourceBase("./www");                
                ContextHandler context = new ContextHandler("/www");
                context.setHandler(resourceHandler);

                ContextHandler contextSniff = new ContextHandler("/sniffer");
                contextSniff.setHandler(SnifferServer.this);

                ServletContextHandler servletContext = new ServletContextHandler(ServletContextHandler.SESSIONS);
                servletContext.setContextPath("/");
                
                ContextHandlerCollection contexts = new ContextHandlerCollection();
                contexts.setHandlers(new Handler[] { context, contextSniff, servletContext });
                
                server.setHandler(contexts);
                try {
                    
                    // Initialize javax.websocket layer
                    ServerContainer wscontainer = WebSocketServerContainerInitializer.configureContext(servletContext);

                    // Add WebSocket endpoint to javax.websocket layer
                    wscontainer.addEndpoint(SnifferSocket.class);

                    log.info("Starting jetty web server at 8080");
                    server.start();
                    server.join();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    log.error("web server error", e);
                } catch (Exception e) {
                    log.error("web server error", e);
                } finally {
                    isRunning = false;
                }
            }
        };
        new Thread(r).start();
    }

    public void stopWS() {
        try {
            server.stop();
        } catch(Exception e) {
            log.warn("failed to stop webserver", e);
        }
    }

    public static SnifferServer getDefault() {
        return Singleton.instance;
    }

    public static void main(String[] args) throws Exception {
        SnifferServer s = SnifferServer.getDefault();
        ExampleAnalyzer analyzer = new ExampleAnalyzer();
        JShark sniff = new JShark(analyzer, new Formatter(s.out));
        sniff.connect("localhost");
        s.setSniffer(sniff);
        s.startWS();
    }

    public PrintStream getOutput() {
        return out;
    }

    private static class Singleton {
        public static final SnifferServer instance = new SnifferServer();
    }
}
