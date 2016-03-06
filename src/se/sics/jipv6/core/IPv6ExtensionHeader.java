package se.sics.jipv6.core;

/* Just as a "TAG" on IPv6ExtensionHeader */
public interface IPv6ExtensionHeader extends IPPayload {
    public void setNext(IPPayload payload);
    public IPPayload getNext();
}
