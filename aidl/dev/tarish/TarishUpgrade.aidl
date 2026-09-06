package dev.tarish;

/**
 * A faster network a Quick Share peer has stood up, and how to reach it.
 *
 * THE DAEMON CANNOT ACT ON THIS ITSELF. Joining a Wi-Fi Direct group or a hotspot is
 * framework API, and tarishsharingd is a native service with no framework access -- the
 * same reason BLE scanning lives in the app. So the daemon decodes the peer's offer, the
 * app joins the network and connects a socket, and the daemon runs the protocol on it.
 * Answer with ITarishService.provideUpgradeSocket.
 *
 * The credentials in here came off the wire from the peer moments ago and are good for
 * one transfer. They are not stored and must not be saved as a network the device will
 * rejoin later.
 */
parcelable TarishUpgrade {
    /**
     * Which kind of network, using the wire protocol's own numbering:
     * 3 = WIFI_HOTSPOT, 8 = WIFI_DIRECT.
     *
     * It decides HOW to join, and the two are not interchangeable. A Wi-Fi Direct group
     * is joined with WifiP2pManager.connect() and a WifiP2pConfig carrying the network
     * name and passphrase; a hotspot is an ordinary access point.
     */
    int medium;

    /** The network name. For Wi-Fi Direct this always begins "DIRECT-". */
    String ssid;

    /** WPA2 passphrase, 8 to 63 characters. */
    String passphrase;

    /**
     * The address to open the TCP connection to once joined, or empty.
     *
     * Empty -- or "0.0.0.0", which is the schema's default and means the same thing --
     * says the peer did not name one, and the app is to use the network's own gateway.
     * For a Wi-Fi Direct group that is the group owner, which the framework reports on
     * connection rather than requiring us to guess it.
     */
    String gateway;

    /** The TCP port the peer is listening on. */
    int port;

    /**
     * The channel the network is on in MHz, or 0 when the peer did not say.
     *
     * A hint, not a requirement: it lets the radio be told where to look instead of
     * scanning every channel. Never treat a mismatch as a reason to refuse.
     */
    int frequency;
}
