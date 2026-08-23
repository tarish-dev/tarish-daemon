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
}
