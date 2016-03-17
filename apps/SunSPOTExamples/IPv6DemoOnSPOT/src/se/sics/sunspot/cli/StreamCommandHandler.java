/*
 * Copyright (c) 2008, Swedish Institute of Computer Science.
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
 * $Id: StreamCommandHandler.java 27 2009-06-06 09:23:21Z nfi $
 *
 * -----------------------------------------------------------------
 *
 * StreamCommandHandler
 *
 * Authors : Joakim Eriksson, Niclas Finne
 * Created : 13 okt 2008
 * Updated : $Date: 2009-06-06 11:23:21 +0200 (Sat, 06 Jun 2009) $
 *           $Revision: 27 $
 */

package se.sics.sunspot.cli;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;

/**
 *
 */
public class StreamCommandHandler extends CommandHandler implements Runnable {

    private InputStream inReader;
    private boolean exit;
    private String prompt;

    public StreamCommandHandler(InputStream in, PrintStream out, PrintStream err, String prompt) {
        super(out, err);
        this.prompt = prompt;
        this.exit = false;
        this.inReader = in;
    }

    public void start() {
        new Thread(this, "cmd").start();
    }

    public void run() {
        String lastLine = null;
        while(!exit) {
            try {
                out.print(prompt);
                out.flush();
                String line = readLine(inReader);
                // Simple execution of last called command line when not running from terminal with history support
                if (((char) 27 + "[A").equals(line)) {
                    line = lastLine;
                }
                if (line != null && line.length() > 0) {
                    lastLine = line;
                    lineRead(line);
                }
            } catch (IOException e) {
                e.printStackTrace();
                err.println("Command line tool exiting...");
                exit = true;
            }
        }
    }

    private String readLine(InputStream in) throws IOException {
        StringBuffer sb = new StringBuffer();
        int c;
        while ((c = in.read()) > 0) {
            if (c == '\n') {
                return sb.toString();
            }
            if (c != '\r') {
                sb.append((char)c);
            }
        }
        return null;
    }

}
