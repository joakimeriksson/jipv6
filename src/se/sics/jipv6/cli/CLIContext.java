/**
 * Copyright (c) 2016, Swedish Institute of Computer Science.
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
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class CLIContext {

    private static final Logger log = LoggerFactory.getLogger(CLIContext.class);

    protected final CLI cli;
    protected final Env env;

    protected final Map<String,String[]> aliases = new ConcurrentHashMap<String,String[]>();

    protected final PrintStream out;
    protected final PrintStream err;
    private List<CommandContext[]> currentAsyncCommands = new ArrayList<CommandContext[]>();

    public CLIContext(CLI cli, PrintStream out, PrintStream err) {
        this.cli = cli;
        this.out = out;
        this.err = err;
        this.env = new Env(cli.getEnv());
        cli.addCLIContext(this);
    }

    public CLI getCLI() {
        return cli;
    }

    public Env getEnv() {
        return env;
    }

    public List<String> getAliases() {
        List<String> list = new ArrayList<>();
        list.addAll(aliases.keySet());
        Collections.sort(list);
        return list;
    }

    public String[] getAlias(String alias) {
        return aliases.get(alias);
    }

    public void addAlias(String alias, String[] commands) {
        aliases.put(alias, commands);
    }

    public void removeAlias(String alias) {
        aliases.remove(alias);
    }

    public abstract void setPrompt(String prompt);

    public int executeCommand(String commandLine) {
        return executeCommand(commandLine, null);
    }

    @SuppressWarnings("resource")
    public int executeCommand(String commandLine, CommandContext context) {
        String[][] parts;
        PrintStream out = context == null ? this.out : context.out;
        PrintStream err = context == null ? this.err : context.err;

        try {
            parts = CommandParser.parseCommandLine(commandLine);
        } catch (Exception e) {
            err.println("Error: failed to parse command:");
            e.printStackTrace(err);
            return -1;
        }
        if (parts == null || parts.length == 0) {
            // Nothing to execute
            return 0;
        }
        Command[] cmds = createCommands(parts);
        if (cmds != null && cmds.length > 0) {
            CommandContext[] commands = new CommandContext[parts.length];
            boolean error = false;
            int pid = -1;
            for (int i = 0; i < parts.length; i++) {
                String[] args = parts[i];
                Command cmd = cmds[i];
                if (i == 0 && cmd instanceof AsyncCommand) {
                    pid = cli.getNextPid();
                }
                commands[i] = new CommandContext(this, commandLine, args, pid,
                        cmd);

                if (i > 0) {
                    PrintStream po = new PrintStream(new LineOutputStream(
                            (LineListener) commands[i].getCommand()));
                    commands[i - 1].setOutput(po, err);
                }
                // Last element also needs output!
                if (i == parts.length - 1) {
                    commands[i].setOutput(out, err);
                }
                // TODO: Check if first command is also LineListener and set it
                // up for input!!
            }
            // Execute when all is set-up in opposite order...
            int index = commands.length - 1;
            try {
                for (; index >= 0; index--) {
                    int code = commands[index].getCommand().executeCommand(
                            commands[index]);
                    if (code != 0) {
                        err.println("command '"
                                + commands[index].getCommandName()
                                + "' failed with error code " + code);
                        error = true;
                        break;
                    }
                }
            } catch (Exception e) {
                err.println("Error: Command failed: " + e.getMessage());
                e.printStackTrace(err);
                error = true;
            }
            if (error) {
                // Stop any commands that have been started
                for (index++; index < commands.length; index++) {
                    commands[index].stopCommand();
                }
                return 1;
            } else if (pid < 0) {
                // The first command is not asynchronous. Make sure all commands
                // have stopped.
                exitCommands(commands);
            } else {
                boolean exited = false;
                for (int i = 0; i < commands.length && !exited; i++) {
                    if (commands[i].hasExited()) {
                        exited = true;
                    }
                }
                if (exited) {
                    exitCommands(commands);
                } else {
                    synchronized (currentAsyncCommands) {
                        currentAsyncCommands.add(commands);
                    }
                }
            }
            return 0;
        }
        return -1;
    }

    private Command[] createCommands(String[][] commandList) {
        Command[] cmds = new Command[commandList.length];
        for (int i = 0; i < commandList.length; i++) {
            commandList[i] = handleAliases(commandList[i]);
            Command command = cli.getCommand(commandList[i][0]);
            if (command == null) {
                err.println("CLI: Command not found: \"" + commandList[i][0]
                        + "\". Try \"help\".");
                return null;
            }
            if (i > 0 && !(command instanceof LineListener)) {
                err.println("CLI: Error, command \"" + commandList[i][0]
                        + "\" does not take input.");
                return null;
            }
            String[] args = Arrays.copyOfRange(commandList[i], 1, commandList[i].length);
            CmdLineParser parser = new CmdLineParser(command);
            try {
                parser.parseArgument(args);
            } catch (CmdLineException | IllegalArgumentException e) {
                boolean classHasArgument = hasAnnotation(command.getClass(), Argument.class);
                boolean classHasOptions  = hasAnnotation(command.getClass(), Option.class);
                err.println("CLI: Error, " + e.getMessage());
                err.println("Usage: " + commandList[i][0]
                            + (classHasOptions ? " [options]" : "")
                            + (classHasArgument ? " arguments" : ""));
                parser.printUsage(err);
                return null;
            }
            cmds[i] = command;
        }
        return cmds;
    }

    private String[] handleAliases(String[] commands) {
        String[] alias = aliases.get(commands[0]);
        if (alias != null) {
            String[] tmp = Arrays.copyOf(alias, alias.length + commands.length - 1);
            System.arraycopy(commands, 1, tmp, alias.length, commands.length - 1);
            if (log.isDebugEnabled()) {
                log.debug("Alias: " + Arrays.toString(commands) + " => " + Arrays.toString(tmp));
            }
            commands = tmp;
        }
        return commands;
    }

    public void exit(CommandContext commandContext, int exitCode, int pid) {
        if (pid < 0 || !removePid(pid)) {
            commandContext.stopCommand();
        }
    }

    List<CommandContext[]> getJobs() {
        // TODO
        return Collections.unmodifiableList(currentAsyncCommands);
    }

    boolean removeJob(int job) {
        CommandContext[] contexts = null;
        synchronized (currentAsyncCommands) {
            if (job > 0 && job <= currentAsyncCommands.size()) {
                contexts = currentAsyncCommands.remove(job - 1);
            }
        }
        return exitCommands(contexts);
    }

    boolean removePid(int pid) {
        CommandContext[] contexts = null;
        synchronized (currentAsyncCommands) {
            for (int i = 0, n = currentAsyncCommands.size(); i < n; i++) {
                CommandContext[] cntx = currentAsyncCommands.get(i);
                if (pid == cntx[0].getPID()) {
                    contexts = cntx;
                    currentAsyncCommands.remove(cntx);
                    break;
                }
            }
        }
        return exitCommands(contexts);
    }

    private boolean exitCommands(CommandContext[] contexts) {
        if (contexts != null) {
            for (CommandContext c : contexts) {
                c.stopCommand();
            }
            return true;
        }
        return false;
    }

    private boolean hasAnnotation(Class<?> type, Class<? extends Annotation> annotation) {
        for (Field f : type.getFields()) {
            if (f.getAnnotation(annotation) != null) {
                return true;
            }
        }
        for (Method m : type.getMethods()) {
            if (m.getAnnotation(annotation) != null) {
                return true;
            }
        }
        return false;
    }

}
