package dev.tarish;

/** Transport state, as tarishsharingd sees it. */
parcelable TarishStatus {
    /** The AWDL link is up and tarishd is holding it. */
    boolean linkUp;
    /** Whether this device is currently discoverable. */
    boolean discoverable;
    /** AWDL channel, 0 if the link is down. */
    int channel;
    /** Regulatory country in use, empty if none. */
    String country;
    /** Peers currently known. */
    int peerCount;
}
