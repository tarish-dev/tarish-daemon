package dev.tarish;

/**
 * A Wi-Fi Direct group this device has stood up for a peer to join.
 *
 * The receiving counterpart to TarishUpgrade: there the peer described a network for us to
 * join, here we describe one for the peer. The fields are the same because they end up in
 * the same wire message -- WifiDirectCredentials inside UPGRADE_PATH_AVAILABLE.
 *
 * Created by the app, because WifiP2pManager is framework API a native service cannot
 * reach. Torn down through removeWifiDirectGroup when the transfer ends: a group left
 * running holds the radio and keeps the device on a network nobody is using.
 */
parcelable TarishGroup {
    /** The network name, always beginning "DIRECT-". Empty if the group could not form. */
    String ssid;

    /** WPA2 passphrase, 8 to 63 characters. */
    String passphrase;

    /**
     * The group owner's address, which is this device -- the peer connects to it.
     *
     * Read from WifiP2pInfo rather than assumed. It is conventionally 192.168.49.1, but
     * that is a convention, and a wrong address here is a peer that joins the group and
     * then cannot reach anything on it.
     */
    String goAddress;

    /** The channel the group formed on in MHz, or 0 when the framework did not say. */
    int frequency;
}
