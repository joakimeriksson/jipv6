/**
 * Copyright (c) 2008-2016, Swedish Institute of Computer Science.
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
 * -----------------------------------------------------------------
 *
 * MiscCommands
 *
 * Author  : Joakim Eriksson
 * Created : 9 mar 2008
 */

package se.sics.jipv6.cli;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.Option;
import org.kohsuke.args4j.spi.RestOfArgumentsHandler;

import se.sics.jipv6.analyzer.JShark;
import se.sics.jipv6.pcap.CapturedPacket;
import se.sics.jipv6.util.Utils;

public class MiscCommands {

    private MiscCommands() {
        // Prevent instances of this class
    }

    @CLICommand(name="ps", topic="core", description="list current executing commands/processes")
    public static class PSCommand implements Command {

//        @Option(name = "-a", usage = "show all commands/processes")
//        private boolean showAll;

        @Override
        public int executeCommand(CommandContext context) {
            CLIContext ctx = context.getCLIContext();
            List<CommandContext[]> jobs = ctx.getJobs();
            if (jobs.size() == 0) {
                context.out.println("No executing commands.");
                return 0;
            }
            context.out.println(" PID\tCommand");
            for (CommandContext[] cc : jobs) {
                CommandContext cmd = cc[0];
                context.out.println("  " + cmd);
            }
            return 0;
        }

    }

    @CLICommand(name="kill", topic="core", description="kill a currently executing command")
    public static class KillCommand implements Command {

//        @Option(name = "-a", usage = "kill process in any context")
//        private boolean killInAll;

        @Argument(usage = "process", metaVar="PID", required=true)
        private int pid;

        @Override
        public int executeCommand(CommandContext context) {
            CLIContext ctx = context.getCLIContext();
            if (ctx.removePid(pid)) {
                return 0;
            }
            context.err.println("could not find the command to kill.");
            return 1;
        }

    }

    @CLICommand(name="alias", topic="core", description="define or display aliases")
    public static class AliasCommand implements Command {

        @Option(name="-p", usage="print in reusable form")
        private boolean isReusable;

//        private String aliasName;
//        private String aliasCommand;
//
//        @Argument(metaVar = "alias='command'", usage = "alias")
//        private void setAlias(final String def) throws CmdLineException {
//            String[] arr = def.split("=");
//            if(arr.length != 2) {
//                throw new CmdLineException(null, "Alias must be specified in the form: "+
//                        "<alias>=<command args...>");
//            }
//            aliasName = arr[0];
//            aliasCommand = arr[1];
//        }

        @Argument(metaVar = "[arg [arg2 [arg3] ...]]", usage = "arguments", handler=RestOfArgumentsHandler.class)
        private List<String> args = new ArrayList<String>();

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            CLIContext ctx = context.getCLIContext();
            if (args.size() > 0) {
                String aliasName = args.get(0);
                int index = aliasName.indexOf('=');
                context.err.println("ALIAS: " + CommandParser.toString(args.toArray(new String[0])));
                if (index <= 0) {
                    String[] cmds = ctx.getAlias(aliasName);
                    if (cmds == null) {
                        context.out.println("No alias with name \"" + aliasName + "\" found.");//
                    } else if (isReusable) {
                        context.out.println("alias " + aliasName + "='" + CommandParser.toString(cmds) + "'");
                    } else {
                        context.out.println("  " + aliasName + "=" + CommandParser.toString(cmds));
                    }
                    return 0;
                } else {
                    String alias = aliasName.substring(0, index);
                    String cmd;
                    if (index == aliasName.length() - 1) {
                        if (args.size() > 1) {
                            cmd = args.get(1);
                        } else {
                            cmd = "";
                        }
                    } else {
                        cmd = aliasName.substring(index + 1);
                    }

                    String[] cmds = CommandParser.parseLine(cmd);
                    // Add new alias
                    if (cmds == null || cmds.length == 0) {
                        context.err.println("No command specified. '" + alias + "' '" + cmd + "' '" + aliasName + "'");
                        return 1;
                    } else if (! ctx.getCLI().hasCommand(cmds[0])) {
                        context.err.println("Could not find the command \"" + cmds[0] + "\".");
                        return 1;
                    } else {
                        ctx.addAlias(alias, cmds);
                        return 0;
                    }
                }
            }

            List<String> aliases = ctx.getAliases();
            if (aliases.size() == 0) {
                context.out.println("No aliases has been defined.");
                return 0;
            }
            for (String alias : aliases) {
                String[] cmd = ctx.getAlias(alias);
                if (cmd == null) {
                    // Ignore
                } else if (isReusable) {
                    context.out.println("alias " + alias + "='" + CommandParser.toString(cmd) + "'");
                } else {
                    context.out.println("  " + alias + "=" + CommandParser.toString(cmd));
                }
            }
            return 0;
        }
    }

    @CLICommand(name="unalias", topic="core", description="remove an alias")
    public static class UnaliasCommand implements Command {

        @Argument(usage = "alias", metaVar="name", required=true)
        private String aliasName;

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            CLIContext ctx = context.getCLIContext();
            // Remove an alias
            if (!ctx.removeAlias(aliasName)) {
                context.err.println("Error: could not find alias '" + aliasName + "'");
                return 1;
            }
            return 0;
        }
    }

    @CLICommand(name="env", topic="core", description="list current environment values")
    public static class EnvCommand implements Command {

        @Override
        public int executeCommand(CommandContext context) {
            CLIContext ctx = context.getCLIContext();
            context.out.println("Available env values:");
            for (String e : ctx.getEnv().getAllKeys()) {
                context.out.println("  " + e + "=" + ctx.getEnv().get(e));
            }
            return 0;
        }

    }

    @CLICommand(name="echo", topic="core", description="echo arguments")
    public static class EchoCommand implements Command {

        @Argument(metaVar = "[arg [arg2 [arg3] ...]]", usage = "arguments")
        private List<String> args = new ArrayList<String>();

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            StringBuilder sb = new StringBuilder();
            for (int i = 0, n = args.size(); i < n; i++) {
                if (i > 0) sb.append(' ');
                sb.append(args.get(i));
            }
            context.out.println(sb.toString());
            return 0;
        }
    }

    @CLICommand(name="quit", topic="core", description="quit")
    public static class QuitCommand implements Command {

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            context.err.println("Bye bye");
            System.exit(0);
            return 0;
        }
    }

    @CLICommand(name="grep", topic="core", description="print lines matching the specified pattern")
    public static class GrepCommand extends BasicLineCommand {

        @Option(name="-i", usage="case insensitive")
        private boolean isIgnoringCase = false;

        @Option(name="-v", usage="invert match")
        private boolean isInverted = false;

        @Argument(usage="pattern", metaVar="PATTERN", required=true)
        private String matching;

        private PrintStream out;
        private Pattern pattern;

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            int flags = isIgnoringCase ? Pattern.CASE_INSENSITIVE : 0;
            pattern = Pattern.compile(matching, flags);
            out = context.out;
            return 0;
        }

        @Override
        public void lineRead(String line) {
            boolean isMatch = pattern.matcher(line).find();
            if(isMatch ^ isInverted) {
                out.println(line);
            }
        }
    }

    @CLICommand(name="trig", topic="core", description="trigg command when getting input")
    public static class TrigCommand extends BasicLineCommand {

        @Argument(metaVar = "[command [arg2 [arg3] ...]]", usage = "arguments", required=true)
        private List<String> args = new ArrayList<String>();

        String command;
        CommandContext context;

        public int executeCommand(CommandContext context) {
            StringBuilder sb = new StringBuilder();
            for (String a : args) {
                if (sb.length() == 0) {
                    sb.append(a);
                } else if (a.indexOf('\'') >= 0) {
                    sb.append(" \"").append(a).append('"');
                } else {
                    sb.append(" '").append(a).append('\'');
                }
            }
            this.command = sb.toString();
            this.context = context;
            context.err.println("CMD: " + command);
            return 0;
        }
        public void lineRead(String line) {
            context.executeCommand(command);
        }
    };

    @CLICommand(name="hexinput", topic="core", description="input a hex packet")
    public static class HexinCommand implements Command {

        @Argument(usage="hexpacket", metaVar="PACKET", required=true)
        private String hexdata;

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            context.out.println("Receive:" + hexdata);
            byte[] packetData = Utils.hexconv(hexdata);
            CapturedPacket packet = new CapturedPacket(System.currentTimeMillis(), packetData);
            JShark.getJShark().packetData(packet);
            return 0;
        }
    }

    @CLICommand(name="channel", topic="core", description="set channel")
    public static class ChannelCommand implements Command {

        @Argument(usage="channel", metaVar="CHANNEL", required=true)
        private int channel;

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            context.out.println("Set channel to:" + channel);
            try {
                JShark.getJShark().getSerialRadio().setRadioChannel(channel);
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return 0;
        }
    }

    @CLICommand(name="panid", topic="core", description="set channel")
    public static class PanidCommand implements Command {

        @Argument(usage="panid", metaVar="PANID", required=true)
        private int panid;

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            context.out.printf("Set panid to: %d 0x%04x\n", panid, panid);
            try {
                JShark.getJShark().getSerialRadio().setRadioPANID(panid);
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return 0;
        }
    }

    @CLICommand(name="radio_mode", topic="core", description="set channel")
    public static class RadioModeCommand implements Command {

        @Argument(usage="mode", metaVar="MODE", required=true)
        private int mode;

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            context.out.printf("Set mode to: %d\n", mode);
            try {
                JShark.getJShark().getSerialRadio().setRadioMode(mode);
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            return 0;
        }
    }

    

    @CLICommand(name="source", topic="core", description="run script")
    public static class SourceCommand implements Command {

        @Option(name="-v", usage="verbose")
        private boolean isVerbose = false;

        private File scriptFile;
        @Argument(usage = "script file", required=true)
        private void setScriptFile(File f) throws CmdLineException {
            if (!f.exists()) {
                throw new IllegalArgumentException("the file '" + f.getAbsolutePath() + "' does not exist");
            }
            if (!f.canRead() || !f.isFile()) {
                throw new IllegalArgumentException("can not read the file '" + f.getAbsolutePath() + "'");
            }
            this.scriptFile = f;
        }

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            try {
                BufferedReader input = new BufferedReader(new FileReader(scriptFile));
                try {
                    String line;
                    int lineNo = 0;
                    int error;
                    while ((line = input.readLine()) != null) {
                        lineNo++;
                        line = line.trim();
                        if (line.length() == 0 || line.startsWith("#")) {
                            // Ignore empty lines and comments
                            continue;
                        }
                        if (isVerbose) context.out.println(line);
                        if ((error = context.executeCommand(line)) != 0) {
                            context.err.println("Error in '" + line + "'");
                            context.err.println("Command returned " + error + " at line " + lineNo + " in file " + scriptFile);
                            break;
                        }
                    }
                } finally {
                    input.close();
                }
                return 0;
            } catch (IOException e) {
                e.printStackTrace(context.err);
                return 1;
            }
        }

    }

}
