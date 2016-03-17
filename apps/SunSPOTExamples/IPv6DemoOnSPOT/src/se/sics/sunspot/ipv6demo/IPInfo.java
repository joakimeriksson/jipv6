package se.sics.sunspot.ipv6demo;

import se.sics.jipv6.http.HttpServer;
import se.sics.jipv6.core.IPStack;
import se.sics.sunspot.cli.BasicCommand;
import se.sics.sunspot.cli.CommandContext;

public class IPInfo extends BasicCommand {

    IPStack stack;
    HttpServer httpd;

    public IPInfo(IPStack st, HttpServer httpd) {
        super("show info of IP Stack", "");
        stack = st;
        this.httpd = httpd;
    }

    public int executeCommand(CommandContext context) {
        stack.printTCPStatus(context.out);
        httpd.printStatus(context.out);
        return 0;
    }
}
