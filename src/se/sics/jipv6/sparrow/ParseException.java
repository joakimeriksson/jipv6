package se.sics.jipv6.sparrow;

import se.sics.jipv6.sparrow.Encap.Error;

public class ParseException extends Exception {

    private static final long serialVersionUID = 2204619127434312106L;
    private final Error error;

    public ParseException(String name) {
        this(name, Error.REQUEST_WITH_ERROR);
    }

    public ParseException(String name, Encap.Error error) {
        super(name);
        this.error = error;
    }

    public Error getEncapError() {
        return error;
    }
}
