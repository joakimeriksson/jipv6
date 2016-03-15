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
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CLI {

    private static final Logger log = LoggerFactory.getLogger(CLI.class);

    private final Env env = new Env();

    private final HashMap<String,CommandInfo> commands = new HashMap<String,CommandInfo>();
    private List<String> names = new ArrayList<String>();
    private boolean isSorted;

    private List<CLIContext> cliContexts = new ArrayList<CLIContext>();
    private int pid = 0;

    public CLI() {
        registerDefaultCommands();
    }

    public Env getEnv() {
        return env;
    }

    synchronized int getNextPid() {
        return ++pid;
    }

    synchronized void addCLIContext(CLIContext ctx) {
        cliContexts.add(ctx);
    }

    synchronized void removeCLIContext(CLIContext ctx) {
        cliContexts.remove(ctx);
    }

    public List<String> getCommandNames() {
        if (!isSorted) {
            ArrayList<String> list = new ArrayList<String>();
            list.addAll(commands.keySet());
            Collections.sort(list);
            names = Collections.unmodifiableList(list);
            isSorted = true;
        }
        return names;
    }

    public Command getCommand(String cmd) {
        CommandInfo info = commands.get(cmd);
        if (info != null) {
            Command c = getCommand(info);
            if (c != null) {
                return c;
            }
        }
//      File scriptFile = new File(scriptDirectory, cmd);
//      if (scriptFile.isFile() && scriptFile.canRead()) {
//          return new ScriptCommand(scriptFile);
//      }
        return null;
    }

    public Command getCommand(CommandInfo info) {
        try {
            Command c = info.commandClass.newInstance();
            return c;
        } catch (InstantiationException | IllegalAccessException e) {
            log.warn("failed to instantiate command '{}'", info.name, e);
            return null;
        }
    }

    public boolean registerCommand(Class<? extends Command> command) {
        CLICommand info = command.getAnnotation(CLICommand.class);
        if (info == null) {
            return false;
        }
        String name = info.name();
        String description = info.description();
        String topic = info.topic();
        if (name == null) {
            return false;
        }
        if (description == null) {
            return false;
        }
        if (commands.get(name) != null) {
            return false;
        }
        commands.put(name, new CommandInfo(name, description, topic, command));
        names.add(name);
        isSorted = false;
        return true;
    }

    public void registerAllCommands(Class<?> type) {
        if (Command.class.isAssignableFrom(type)) {
            log.debug("adding {} as command", type.getName());
            if (!registerCommand(type.asSubclass(Command.class))) {
                log.debug("failed to register as command");
            }
        }
        for (Class<?> subClass : type.getDeclaredClasses()) {
            if (Modifier.isStatic(subClass.getModifiers())
                    && Modifier.isPublic(subClass.getModifiers())
                    && Command.class.isAssignableFrom(subClass)) {
                log.debug("adding inner class {} as command", subClass.getName());
                if (!registerCommand(subClass.asSubclass(Command.class))) {
                    log.debug("failed to register as command");
                }
            }
        }
    }

    protected void registerDefaultCommands() {
        registerCommand(HelpCommand.class);
        registerCommand(ExecCommand.class);
        registerCommand(ScriptCommand.class);

        env.put(FileCommands.TARGET_MAP_NAME, new TargetMap());
        registerAllCommands(FileCommands.class);

        registerAllCommands(MiscCommands.class);
    }

    private int printUsage(PrintStream out, String commandName) {
        CommandInfo info = commands.get(commandName);
        Command command;
        if (info == null || (command = getCommand(info)) == null) {
            out.println("could not find the command '" + commandName + "'");
            return 1;
        }

        CmdLineParser parser = new CmdLineParser(command);
        if (info.topic.length() > 0) {
            out.println("[" + info.topic + "] " + commandName + " - " + info.description);
        } else {
            out.println(commandName + " - " + info.description);
        }
        parser.printUsage(out);
        return 0;
    }

    public static class CommandInfo {
        public final String name;
        public final String description;
        public final String topic;
        public final Class<? extends Command> commandClass;

        CommandInfo(String name, String description, String topic, Class<? extends Command> commandClass) {
            this.name = name;
            this.description = description;
            this.topic = topic == null ? "" : topic;
            this.commandClass = commandClass;
        }
    }

    @CLICommand(name="help", topic="core", description="shows help for command or command list")
    public static class HelpCommand implements Command {

        @Option(name = "-t", usage = "topic", metaVar = "TOPIC")
        private String topic;

        @Argument(metaVar = "[cmd [cmd2 [cmd3] ...]]", usage = "commands")
        private List<String> commands = new ArrayList<String>();

        @Override
        public int executeCommand(CommandContext context) {
            CLI cli = context.getCLI();
            if (commands.size() == 1) {
                return cli.printUsage(context.out, commands.get(0));
            }
            if (commands.size() == 0) {
                // No commands specified - show all available commands
                commands = cli.getCommandNames();
                context.out.println("Available commands:");
            }
            int maxCmd = 0;
            for (String c : commands) {
                if (c.length() > maxCmd) {
                    maxCmd = c.length();
                }
            }
            String format = "%-" + maxCmd + "s  %s\n";
            for (String c : commands) {
                CommandInfo info = cli.commands.get(c);
                if (info == null) {
                    context.err.println("CLI: could not find the command '" + c + "'");
                    return 1;
                }
                if (topic != null && !topic.equals(info.topic)) {
                    continue;
                }
                context.out.printf(format, c, info.description);
            }
            return 0;
        }

    }

}
