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
 */

package se.sics.jipv6.cli;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.kohsuke.args4j.Argument;
import org.kohsuke.args4j.Option;

public class FileCommands {

    public static final String TARGET_MAP_NAME = "fileTargets";

    private FileCommands() {
        // Prevent instances of this class
    }

    @CLICommand(name=">", topic="file", description="redirect to file (overwrite)")
    public static class FileWriteCommand extends FileTargetCommand {

        public FileWriteCommand() {
            super(false, false);
        }

    }

    @CLICommand(name=">>", topic="file", description="redirect to file (append)")
    public static class FileAppendCommand extends FileTargetCommand {

        public FileAppendCommand() {
            super(false, true);
        }

    }

    @CLICommand(name="tee", topic="file", description="redirect to file and standard out")
    public static class TeeCommand extends FileTargetCommand {

        public TeeCommand() {
            super(true, true);
        }

    }

    @CLICommand(name="fclose", topic="file", description="close the specified files")
    public static class CloseCommand implements Command {

        @Option(name = "-a", usage = "close all open files")
        private boolean closeAll = false;

        @Argument(metaVar = "[file [file2 [file3] ...]]", usage = "files")
        private List<String> files = new ArrayList<String>();

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            TargetMap fileTargets = context.getEnv().getRequired(TargetMap.class, TARGET_MAP_NAME);
            if (closeAll) {
                files = fileTargets.getAllTargetNames();
            }
            for (String file : files) {
                Target ft = fileTargets.get(file);
                if (ft != null) {
                    context.out.println("Closing file " + file);
                    ft.close();
                } else {
                    context.err.println("Could not find any open file with name '" + file + "'");
                    return 1;
                }
            }
            return 0;
        }
    }

    @CLICommand(name="files", topic="file", description="list open files")
    public static class ListCommand implements Command {

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            TargetMap fileTargets = context.getEnv().getRequired(TargetMap.class, TARGET_MAP_NAME);
            List<Target> targets = fileTargets.getAllTargets();
            if (targets == null || targets.size() == 0) {
                context.out.println("There are no open files.");
            } else {
                for (Target type : targets) {
                    context.out.println(type.getStatus());
                }
            }
            return 0;
        }

    }

    protected static class FileTargetCommand extends BasicLineCommand {

        private final boolean print;
        private final boolean append;

        @Argument(metaVar = "file", usage = "file")
        private String fileName;

        private Target ft;
        private CommandContext context;
        private TargetMap fileTargets;

        public FileTargetCommand(boolean print, boolean append) {
            this.print = print;
            this.append = append;
        }

        @Override
        public int executeCommand(CommandContext context) throws CLIException {
            if (fileName == null) {
                throw new CLIException("no target file specified");
            }
            this.fileTargets = context.getEnv().getRequired(TargetMap.class, TARGET_MAP_NAME);
            this.context = context;

            IOException error = null;
            boolean alreadyOpened = false;

            synchronized (fileTargets) {
                ft = fileTargets.get(fileName);
                if (ft == null) {
                    try {
                        FileWriter writer = new FileWriter(fileName, append);
                        ft = new FileTarget(fileTargets, fileName, writer);
                    } catch (IOException e) {
                        error = e;
                    }
                } else if (!append) {
                    alreadyOpened = true;
                }
            }

            if (error != null) {
                error.printStackTrace(context.err);
                return -1;
            }
            if (alreadyOpened) {
                context.err.println("File already opened: can not overwrite");
                return -1;
            }
            if (context.getPID() >= 0) {
                ft.addContext(context);
            }
            return 0;
        }

        @Override
        public void lineRead(String line) {
            if (print) {
                context.out.println(line);
            }
            ft.lineRead(context, line);
        }

        @Override
        public void stopCommand(CommandContext context) {
            if (ft != null) {
                ft.removeContext(context);
            }
        }
    }
}
