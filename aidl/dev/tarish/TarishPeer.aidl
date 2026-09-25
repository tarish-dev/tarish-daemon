package dev.tarish;

/** A peer discovered on the AWDL link. */
parcelable TarishPeer {
    /** Stable within a session; what sendFiles() takes. */
    String id;
    /** Human-readable, as advertised by the peer. */
    String name;
    /** Device model if the peer advertises one, else empty. */
    String model;
    /** Signal strength in dBm; 0 if unknown. */
    int rssi;
    /**
     * Which protocol found this peer — one of ITarishService.PROTOCOL_*.
     *
     * Tarish speaks two protocols to two different worlds, and they are not
     * interchangeable: an Apple device reachable over AirDrop cannot be sent to over
     * Quick Share, and the reverse. A person choosing a device is choosing a protocol
     * whether or not the UI admits it, so the UI says it.
     */
    int protocol;
    /**
     * How to open a connection to this peer when there is no network, or empty.
     *
     * Quick Share peers found over BLE carry a Bluetooth Classic MAC in their
     * advertisement; that address is the whole point of BLE discovery, since the
     * advertisement itself carries nothing to connect to. Empty means the peer published
     * no address -- it advertised the short form, or it has no BR/EDR listener -- and it
     * is therefore discoverable but not reachable this way.
     *
     * Always empty for AirDrop peers, which are reached over AWDL by link-local address.
     */
    String bluetoothMac;

    /**
     * The address the peer is ADVERTISING from, which is not its Bluetooth MAC.
     *
     * An L2CAP connection-oriented channel rides the LE link, so it is opened to this
     * address rather than to bluetoothMac. It is usually a resolvable private address
     * and ROTATES -- we have seen three in as many minutes for one phone -- so it is
     * only good for as long as the advertisement that carried it. Dial promptly and do
     * not cache it.
     */
    String bleAddress;

    /**
     * The L2CAP PSM the peer is listening on, or 0 if it published none.
     *
     * **This decides which socket to open, and it is not a preference.** A peer that
     * publishes a PSM refuses an RFCOMM connection on the Nearby service -- accepted and
     * closed inside 200 ms, no frame either way. A peer that publishes none accepts
     * RFCOMM and completes whole transfers. Measured on a Pixel and a Windows machine
     * side by side, with both off Wi-Fi.
     */
    int psm;

    /**
     * Whether the peer will take a transfer right now -- one of ITarishService.STATE_*.
     *
     * STATE_SCREEN_OFF means the device is still on the link and still answering, but its
     * owner locked it or switched AirDrop off. Both look identical on the air and both
     * refuse an offer, so the app shows the same thing stock does: the tile stays for a
     * few seconds labelled "screen off", then goes. It comes back the moment the device
     * is receptive again, without waiting for rediscovery.
     *
     * Read off the peer's BLE state message, not off mDNS -- iOS withdraws nothing over
     * mDNS when it locks, which is why this field exists. Always STATE_RECEPTIVE for
     * Quick Share peers: a Quick Share device that stops being receptive stops
     * advertising, and simply drops out of the list.
     *
     * APPENDED LAST -- parcelable fields are positional too.
     */
    int state;
}
