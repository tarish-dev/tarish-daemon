package dev.barq;

/** Transport state, as barqsharingd sees it. */
parcelable BarqStatus {
    /** The AWDL link is up and barqd is holding it. */
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
