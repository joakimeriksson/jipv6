/**
 * Copyright (c) 2010-2016, Swedish Institute of Computer Science.
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
 * -----------------------------------------------------------------
 *
 * Target
 *
 * Author  : Joakim Eriksson, Niclas Finne
 * Created : 14 mar 2010
 */
package se.sics.jipv6.cli;
import java.util.ArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class Target {

    private static final Logger log = LoggerFactory.getLogger(Target.class);

    protected static final boolean DEBUG = false;

    private final TargetMap targets;
    private final String name;
    private final boolean autoclose;
    private ArrayList<CommandContext> contexts = new ArrayList<CommandContext>();
    private Object lock = new Object();

    protected Target(TargetMap targets, String name, boolean autoclose) {
        this.targets = targets;
        this.name = name;
        this.autoclose = autoclose;
        targets.put(name, this);
    }

    public String getName() {
        return name;
    }

    public String getStatus() {
        StringBuilder sb = new StringBuilder();
        sb.append(name);
        synchronized (lock) {
            if (contexts != null) {
                sb.append(" \tPIDs: [");
                for (int i = 0, n = contexts.size(); i < n; i++) {
                    int pid = contexts.get(i).getPID();
                    if (i > 0) {
                        sb.append(',');
                    }
                    if (pid < 0) {
                        sb.append('?');
                    } else {
                        sb.append(pid);
                    }
                }
                sb.append(']');
            }
        }
        return sb.toString();
    }

    public final void lineRead(CommandContext context, String line) {
        if (line == null) {
            removeContext(context);
        } else {
            handleLine(context, line);
        }
    }

    protected abstract void handleLine(CommandContext context, String line);

    public void addContext(CommandContext context) {
        boolean added = false;
        synchronized (lock) {
            if (contexts != null) {
                contexts.add(context);
                added = true;
                if (DEBUG) {
                    log.debug("new writer to {} ({})", name, contexts.size());
                }
            }
        }
        if (!added) {
            context.kill();
        }
    }

    public void removeContext(CommandContext context) {
        boolean close = false;
        synchronized (lock) {
            if (contexts != null) {
                if (contexts.remove(context)) {
                    if (DEBUG) {
                        log.debug("removed writer from {} ({})", name, contexts.size());
                    }
                }
                if (contexts.size() == 0) {
                    close = true;
                }
            }
        }
        if (close && autoclose) {
            close(false);
        }
    }

    public void close() {
        close(true);
    }

    private void close(boolean forceClose) {
        ArrayList<CommandContext> list;
        synchronized (lock) {
            if (contexts == null) {
                // Already closed
                return;
            }
            if (contexts.size() > 0 && !forceClose) {
                // Target still has connected writers.
                return;
            }
            list = contexts;
            contexts = null;
        }

        if (targets.removeTarget(name, this)) {
            if (DEBUG) {
                log.debug("closed file {}", name);
            }
        }

        if (list != null) {
            // Close any connected writers
            for (CommandContext context : list) {
                context.kill();
            }
        }
        closeTarget();
    }

    protected abstract void closeTarget();

}
