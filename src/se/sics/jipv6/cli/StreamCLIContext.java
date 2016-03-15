/*
 * Copyright (c) 2008-2016, Swedish Institute of Computer Science.
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
 * -----------------------------------------------------------------
 *
 * StreamCommandHandler
 *
 * Authors : Joakim Eriksson, Niclas Finne
 * Created : 13 okt 2008
 */

package se.sics.jipv6.cli;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.InterruptedIOException;
import java.io.PrintStream;

/**
 *
 */
public class StreamCLIContext extends CLIContext {

    private BufferedReader inReader;
    private boolean exit = false;
    private String prompt;
    private boolean isRunning;
    private boolean useWorkaround;

    public StreamCLIContext(CLI cli, InputStream in, PrintStream out,
            PrintStream err, String prompt) {
        super(cli, out, err);
        this.prompt = prompt;
        this.inReader = new BufferedReader(new InputStreamReader(in));
        useWorkaround = Boolean.getBoolean("cli.stream.workaround");
        start();
    }

    @Override
    public void setPrompt(String prompt) {
        this.prompt = prompt;
    }

    private void start() {
        if (!isRunning) {
            isRunning = true;
            new Thread(new Runnable() {
                @Override public void run() {
                    try {
                        String lastLine = null;
                        while (!exit) {
                            out.print(prompt);
                            out.flush();
                            String line = useWorkaround ? readLine(inReader) : inReader.readLine();
                            // Simple execution of last called command line when not running
                            // from terminal with history support
                            if (((char) 27 + "[A").equals(line)) {
                                line = lastLine;
                            }
                            if (line != null && line.length() > 0) {
                                lastLine = line;
                                executeCommand(line);
                            }
                        }
                    } catch (IOException e) {
                        e.printStackTrace(err);
                        err.println("Command line tool exiting...");
                        exit = true;
                    } finally {
                        isRunning = false;
                    }
                }
            }, "cmd").start();
        }
    }

    private String readLine(BufferedReader input) throws IOException {
        StringBuilder str = new StringBuilder();
        while (true) {
            if (input.ready()) {
                int c = input.read();
                if (c == '\n') {
                    return str.toString();
                }
                if (c != '\r') {
                    str.append((char) c);
                }
            } else {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    throw new InterruptedIOException();
                }
            }
        }
    }

}
