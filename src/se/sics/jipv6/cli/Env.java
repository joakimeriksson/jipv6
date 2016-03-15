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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public class Env {

    protected final Env parentEnv;
    protected final Map<String,Object> map = new ConcurrentHashMap<>();

    public Env() {
        this(null);
    }

    public Env(Env parentEnv) {
        this.parentEnv = parentEnv;
    }

    public List<String> getAllKeys() {
        Set<String> set = new HashSet<>();
        if (parentEnv != null) {
            set.addAll(parentEnv.map.keySet());
        }
        set.addAll(map.keySet());

        List<String> list = new ArrayList<>();
        list.addAll(set);
        Collections.sort(list);
        return list;
    }

    public Object get(String key) {
        Object v = map.get(key);
        return v == null && parentEnv != null ? parentEnv.get(key) : v;
    }

    public Object get(String key, Object defaultValue) {
        Object v = map.get(key);
        if (v != null) {
            return v;
        }
        return parentEnv != null ? parentEnv.get(key, defaultValue) : defaultValue;
    }

    public <T> T get(Class<T> type, String key) {
        return get(type, key, null);
    }

    public <T> T get(Class<T> type, String key, T defaultValue) {
        Object v = map.get(key);
        if (type.isInstance(v)) {
            return type.cast(v);
        }
        if (parentEnv != null) {
            return parentEnv.get(type,  key, defaultValue);
        }
        return defaultValue;
    }

    public <T> T getRequired(Class<T> type, String key) throws CLIException {
        T value = get(type, key, null);
        if (value == null) {
            throw new CLIException("env property '" + key + "' does not exist or is of wrong type");
        }
        return value;
    }

    public Object put(String key, Object value) {
        return map.put(key, value);
    }

    public String getProperty(String key) {
        return getProperty(key, null);
    }

    public String getProperty(String key, String defaultValue) {
        Object v = get(key);
        return v instanceof String ? (String)v : defaultValue;
    }

    public long getProperty(String key, long defaultValue) {
        Object v = get(key);
        return v instanceof Long ? (Long)v : defaultValue;
    }

    public double getProperty(String key, double defaultValue) {
        Object v = get(key);
        return v instanceof Double ? (Double)v : defaultValue;
    }

    public void setProperty(String key, String value) {
        map.put(key,  value);
    }

}
