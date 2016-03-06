package se.sics.sunspot.ipv6demo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

import se.sics.sunspot.cli.CommandContext;
import se.sics.sunspot.cli.CommandHandler;

public class CLISession implements Runnable {

  InputStream in;
  OutputStream out;
  PrintStream pout;
  CommandContext context;
  private boolean prompt = false;
  
  public CLISession(CommandHandler ch, InputStream in, OutputStream out) {
    this.in = in;
    this.out = out;
    
    pout = new PrintStream(out);
    context = new CommandContext(ch, null, null, 0, null, pout, pout);
    new Thread(this).start();
  }
  
  public void run() {
    System.out.println("CLISession reader thread started...");
    boolean escape = false;
    int option = 0;
    StringBuffer buff = new StringBuffer();
    int c = 0;
    try {
      while ((c = in.read()) != -1) {
        if (option != 0) {
          /* currently ignores all options... */
          option = 0;
        } else if (escape) {
          if (c == 244) { // break / interrupt
            return;
          }
          /* go to option mode ... */
          if (c == 253 || c == 251) {
            option = c;
          }
          escape = false;
        } else if (c == '\n' || c == '\r') {
          String cmd = buff.toString().trim();
          System.out.println("Command to execute: " + cmd);
          if (cmd.length() > 0) {
            context.executeCommand(cmd);
            if (prompt ) pout.print("SPOT CLI>");
            /* ensure that the data is flushed immediately */
            out.flush();
          }
          buff.setLength(0);
        } else if (c == 255){
          escape = true;
        } else {
          buff.append((char) c);
        }
      }
    } catch (IOException e) {
      e.printStackTrace();
    } finally {
      try {
        in.close();
        out.close();
      } catch (IOException e) {    
      }
    }
  }
}