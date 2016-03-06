package se.sics.sunspot.cli;
import java.io.PrintStream;
import se.sics.jipv6.util.Utils;

public class CommandContext {

  private String[] args;
  private String commandLine;
  private int pid = -1;
  private boolean exited = false;
  private Command command;

  public PrintStream out;
  public PrintStream err;
  private CommandHandler commandHandler;

  public CommandContext(CommandHandler ch, LineListener output) {
    this(ch, null, null, 0, null);
    LineOutputStream lOut = new LineOutputStream(output);
    PrintStream pOut = new PrintStream(lOut);
    setOutput(pOut, pOut);
  }
  
  public CommandContext(CommandHandler ch, String commandLine, String[] args,
                        int pid, Command command, PrintStream out, PrintStream err) {
    this(ch, commandLine, args, pid, command);
    setOutput(out, err);
  }

  public CommandContext(CommandHandler ch, String commandLine, String[] args,
                        int pid, Command command) {
    this.commandLine = commandLine;
    this.args = args;
    this.pid = pid;
    this.command = command;
    this.commandHandler = ch;
  }

  void setOutput(PrintStream out, PrintStream err) {
    this.out = out;
    this.err = err;
  }

  Command getCommand( ) {
    return command;
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
   * @param exitCode - the exit code of the command
   */
  public void exit(int exitCode) {
    // TODO: Clean up can be done now!
    exited = true;
    commandHandler.exit(this, exitCode, pid);
  }

  public String getCommandName() {
    return args[0];
  }

  public int getArgumentCount() {
    return args.length - 1;
  }

  public String getArgument(int index) {
    return args[index + 1];
  }

  public int getArgumentAsInt(int index) {
    return getArgumentAsInt(index, 0);
  }

  public int getArgumentAsInt(int index, int defaultValue) {
    try {
      return Utils.decodeInt(getArgument(index));
    } catch (Exception e) {
      err.println("Illegal number format: " + getArgument(index));
      return defaultValue;
    }
  }

  public long getArgumentAsLong(int index) {
    return getArgumentAsLong(index, 0L);
  }

  public long getArgumentAsLong(int index, long defaultValue) {
    try {
      return Utils.decodeLong(getArgument(index));
    } catch (Exception e) {
      err.println("Illegal number format: " + getArgument(index));
      return defaultValue;
    }
  }

  public float getArgumentAsFloat(int index) {
    return getArgumentAsFloat(index, 0f);
  }

  public float getArgumentAsFloat(int index, float defaultValue) {
    try {
      return Float.parseFloat(getArgument(index));
    } catch (Exception e) {
      err.println("Illegal number format: " + getArgument(index));
      return defaultValue;
    }
  }

  public double getArgumentAsDouble(int index) {
    return getArgumentAsDouble(index, 0.0);
  }

  public double getArgumentAsDouble(int index, double defaultValue) {
    String arg = getArgument(index);
    try {
      return Double.parseDouble(arg);
    } catch (Exception e) {
      err.println("Illegal number format: " + getArgument(index));
      return defaultValue;
    }
  }

  public boolean getArgumentAsBoolean(int index) {
    String v = getArgument(index);
    return "true".equalsIgnoreCase(v) || "1".equals(v);
  }

  public int executeCommand(String command) {
    return commandHandler.executeCommand(command, this);
  }

  public String toString() {
    return (pid >= 0 ? ("" + pid) : "?") + '\t' + (commandLine == null ? getCommandName() : commandLine);
  }

}
