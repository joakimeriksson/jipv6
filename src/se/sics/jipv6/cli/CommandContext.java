/**
 * Copyright (c) 2007-2016, Swedish Institute of Computer Science.
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
 */

package se.sics.jipv6.cli;
import java.io.PrintStream;

public class CommandContext {

    private String[] args;
    private String commandLine;
    private int pid = -1;
    private boolean exited = false;
    private Command command;

    public PrintStream out;
    public PrintStream err;
    private CLIContext cliContext;

    public CommandContext(CLIContext ch, String commandLine, String[] args,
            int pid, Command command) {
        this.commandLine = commandLine;
        this.args = args;
        this.pid = pid;
        this.command = command;
        this.cliContext = ch;
    }

    public CLI getCLI() {
        return cliContext.getCLI();
    }

    public CLIContext getCLIContext() {
        return cliContext;
    }

    public Env getEnv() {
        return cliContext.getEnv();
    }

    void setOutput(PrintStream out, PrintStream err) {
        this.out = out;
        this.err = err;
    }

    Command getCommand() {
        return command;
    }

    // Called by CommandHandler to stop this command.
    void stopCommand() {
        if (!exited) {
            exited = true;

            if (command instanceof AsyncCommand) {
                AsyncCommand ac = (AsyncCommand) command;
                ac.stopCommand(this);
            }
        }
    }

    String getCommandLine() {
        return commandLine;
    }

    public int getPID() {
        return pid;
    }

    public boolean hasExited() {
        return exited;
    }

    /**
     * exit needs to be called as soon as the command is completed (or stopped).
     *
     * @param exitCode - the exit code of the command
     */
    public void exit(int exitCode) {
        // TODO: Clean up can be done now!
        exited = true;
        cliContext.exit(this, exitCode, pid);
    }

    // Requests that this command chain should be killed. Used by for example
    // FileTarget to close all connected commands when the file is closed.
    void kill() {
        if (!exited) {
            cliContext.exit(this, -9, pid);
        }
    }

    public String getCommandName() {
        return args[0];
    }

    public int executeCommand(String command) {
        return cliContext.executeCommand(command, this);
    }

    public String toString() {
        return (pid >= 0 ? ("" + pid) : "?") + '\t'
                + (commandLine == null ? getCommandName() : commandLine);
    }

}
