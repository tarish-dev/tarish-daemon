package dev.barq;

/** A peer discovered on the AWDL link. */
parcelable BarqPeer {
    /** Stable within a session; what sendFiles() takes. */
    String id;
    /** Human-readable, as advertised by the peer. */
    String name;
    /** Device model if the peer advertises one, else empty. */
    String model;
    /** Signal strength in dBm; 0 if unknown. */
    int rssi;
    /**
     * Which protocol found this peer — one of IBarqService.PROTOCOL_*.
     *
     * Barq speaks two protocols to two different worlds, and they are not
     * interchangeable: an Apple device reachable over AirDrop cannot be sent to over
     * Quick Share, and the reverse. A person choosing a device is choosing a protocol
     * whether or not the UI admits it, so the UI says it.
     */
    int protocol;
}
