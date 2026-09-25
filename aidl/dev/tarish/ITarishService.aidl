package dev.tarish;

import dev.tarish.ITarishCallback;
import dev.tarish.TarishPeer;
import dev.tarish.TarishGroup;
import dev.tarish.TarishPolicy;
import dev.tarish.TarishStatus;

/**
 * The contract between tarishd and its clients.
 *
 * It lives with the DAEMON because the daemon is the server: it defines the
 * protocol, and a client is written against it. The app repo consumes this file
 * rather than declaring its own copy, so the two cannot drift apart silently.
 *
 * Everything expensive — holding the AWDL link, discovery, mDNS, the transfer
 * itself — happens in tarishd. A client is expected to be an ordinary app that is
 * NOT running most of the time: it binds when the user is looking at it, and
 * receives nothing when it is closed. That is the whole reason for the split, so
 * no method here should require the client to stay alive.
 */
interface ITarishService {
    /** Current transport state: link up, channel, country, peer count. */
    TarishStatus getStatus();

    /**
     * Make this device discoverable. durationSeconds of 0 means indefinitely.
     * Visibility is the DAEMON's state, not the app's, so it survives a client
     * that is merely rebinding.
     *
     * It does NOT survive the radio being released: setActive(false) eventually
     * takes AWDL down, and nothing is reachable without it. Visibility outliving
     * the client is about not losing state across a rebind, not about receiving
     * files with the app closed -- /Ask refuses those anyway.
     */
    void setDiscoverable(boolean discoverable, int durationSeconds);

    /**
     * Whether a client is in the foreground and needs the transport.
     *
     * This, not setDiscoverable, is what governs the AWDL radio. The two are
     * deliberately separate: a client that is SENDING is not discoverable and
     * still needs the link, so gating the radio on visibility would tear it down
     * underneath every outgoing transfer.
     *
     * Call it on every onResume and onPause. A client bouncing through a file
     * picker toggles the foreground several times a second, and the daemon applies
     * its own hold-off, so this is cheap to call and safe to call often.
     *
     * Never calling it is safe: the daemon holds the radio up. That costs battery
     * -- an idle AWDL session is not free, it runs vendor threads -- but sharing
     * keeps working, which is the right way round for a client that has not been
     * updated.
     *
     * staFrequencyMhz is the frequency the device's Wi-Fi is currently associated
     * on, 0 if it is not associated, or -1 if the adapter is off. It is passed HERE
     * rather than through its own call so there is no window where the daemon knows
     * it should bring the radio up but not yet which band is safe.
     *
     * The three values are NOT interchangeable. The daemon remembers the last real
     * frequency and treats 0 as "no news", because raising AWDL on a chip that cannot
     * hold both destroys the association it would otherwise read. -1 says the adapter
     * is off, which is the one case where the memory is wrong rather than stale: there
     * is no association to protect, and remembering one keeps AWDL out of 5 GHz for
     * nothing.
     *
     * The client is the only component that can see this. Both daemons are native
     * and have no framework access, and nothing exposes the association frequency
     * as a file either daemon can read.
     */
    void setActive(boolean active, int staFrequencyMhz);

    /** Peers currently known. Fresh as of the last discovery round. */
    TarishPeer[] getPeers();


    /**
     * Offer files to a peer. The client passes already-open descriptors so the
     * daemon never needs storage permissions or access to the client's files.
     * Returns a transfer id used by the callbacks.
     */
    long sendFiles(String peerId, in ParcelFileDescriptor[] files, in String[] names);

    /** Answer an incoming offer previously delivered via onTransferOffered. */
    void respondToOffer(long transferId, boolean accept);

    /** Cancel a transfer in either direction. */
    void cancelTransfer(long transferId);

    /**
     * Names of files the daemon has received and not yet handed over.
     *
     * Leaf names only, never paths: the daemon extracted them and the client has no
     * business constructing a path into the daemon's storage.
     */
    String[] getReceivedFiles();

    /**
     * Open one received file for reading.
     *
     * Deliberately a file descriptor rather than a shared directory. The daemon runs as
     * `nobody` with 0700 storage that nothing else can reach, and passing an already-open
     * fd over binder means the client never needs read access to that directory at all --
     * no file-context grant, no group juggling, and no way to reach anything the daemon
     * did not hand over.
     */
    ParcelFileDescriptor openReceivedFile(String name);

    /** Drop a received file once the client has stored it somewhere the user can see. */
    void deleteReceivedFile(String name);

    /**
     * Register for events. The daemon holds the callback weakly and keeps
     * working when no client is bound — an unanswered incoming offer is surfaced
     * by the daemon itself, not by requiring a client to be running.
     */
    void registerCallback(ITarishCallback cb);
    void unregisterCallback(ITarishCallback cb);

    /**
     * Forget every discovered peer and browse again from scratch.
     *
     * getPeers() already asks for a fresh query but does not DISCARD what is known,
     * so a peer that has gone away stays listed until its TTL expires and one that
     * never fully resolved stays half-resolved. This drops the table, the
     * resolved-name cache and the probe record, then re-queries.
     *
     * DECLARED LAST, AND NEW METHODS MUST BE TOO. AIDL numbers transactions by
     * position, so inserting one in the middle renumbers every method below it. This
     * was originally added after getPeers(), which silently shifted sendFiles and
     * everything after — the call then lands on the wrong method and the failure is a
     * bare NullPointerException out of Parcel.createExceptionOrNull, naming nothing.
     */
    void refreshPeers();

    /** AirDrop — Apple devices. */
    const int PROTOCOL_AIRDROP = 0;
    /** Quick Share — Android and Windows. */
    const int PROTOCOL_QUICKSHARE = 1;

    /** Neither direction is permitted. */
    const int MODE_OFF = 0;
    /** May be discovered and may accept incoming transfers; may not send. */
    const int MODE_RECEIVE = 1;
    /** May discover peers and send; is not discoverable and refuses incoming. */
    const int MODE_SEND = 2;
    const int MODE_BOTH = 3;

    /** TarishPeer.state: the peer will take a transfer now. */
    const int STATE_RECEPTIVE = 0;
    /**
     * TarishPeer.state: present on the link but not receptive -- screen locked, or
     * AirDrop switched off. The same thing on the air, and the same thing for a sender.
     */
    const int STATE_SCREEN_OFF = 1;

    /**
     * Install the policy this device is to enforce.
     *
     * ENFORCEMENT LIVES HERE, NOT IN THE APP. tarishsharingd is what advertises, browses,
     * accepts connections and writes files, so it has to be the thing that refuses. An
     * app that merely hides the affordance is bypassed by killing the app and talking to
     * the daemon directly, which is not a policy control at all.
     *
     * The daemon starts DENIED and opens only on being told, so a daemon that has never
     * heard from the app shares nothing. That is the opposite of the radio gate, where an
     * unset property means radio-ON — right there, because a missing property should not
     * silently disable sharing, and wrong here, where a missing policy must not silently
     * permit it. Do not copy the pattern across.
     *
     * The app calls this on every bind, not only on change: the daemon holds policy in
     * memory and a restart must not leave it running on a stale grant.
     */
    void setPolicy(in TarishPolicy policy);

    /** What the daemon is currently enforcing, for the settings screen to render. */
    TarishPolicy getPolicy();

    /**
     * Change the advertised name, persisting it across reboots.
     *
     * The app cannot write this itself: the name lives in `persist.tarish.name`, and
     * setting a persist property needs a policy grant the app does not have and should
     * not be given. Passing empty restores the device-model default.
     */
    void setDeviceName(String name);

    /** The name currently advertised, resolved through the same fallbacks the daemon uses. */
    String getDeviceName();

    /**
     * Report a Quick Share BLE advertisement the app saw.
     *
     * THE APP OWNS THE RADIO; THE DAEMON OWNS THE PROTOCOL. A native daemon cannot reach
     * framework Bluetooth, so the app scans -- but it forwards the raw service data
     * rather than decoding it, because the decoder lives in libtarish_protocol with test
     * vectors captured from real devices. Parsing it a second time in Java would be a
     * second thing to get wrong, and the two would drift.
     *
     * Peers reported this way appear in getPeers() with PROTOCOL_QUICKSHARE, and expire
     * on their own if the app stops seeing them.
     *
     * `address` is the peer's BLE address, which is usually randomised and rotates; it is
     * used only to dedupe within a session, never as an identity.
     */
    void reportBlePeer(String address, int rssi, in byte[] serviceData);

    /**
     * Send files to a Quick Share peer over a socket the CALLER already connected.
     *
     * The daemon cannot open this connection itself. Reaching a peer with no network
     * means Bluetooth, and framework Bluetooth is unreachable from a native service --
     * the same reason BLE scanning lives in the app. So the app connects and hands the
     * socket over; the daemon runs the protocol on it, which is the half that is tested.
     *
     * `socket` is one end of a socket pair, not the Bluetooth socket itself: Android does
     * not expose a BluetoothSocket's descriptor through public API. The app pumps bytes
     * between the two. That costs a copy in each direction and avoids reflecting into
     * hidden platform fields, which is the kind of thing that breaks on an OS update
     * with no warning.
     *
     * Returns a transfer id, or 0 if the send could not be started.
     */
    long sendFilesOnSocket(String peerId, in ParcelFileDescriptor socket,
            in ParcelFileDescriptor[] files, in String[] names);

    /**
     * Submit the PIN the user read off the receiving device.
     *
     * Returns true if it matches the one this transfer derived, in which case the
     * transfer proceeds. False means wrong digits -- the transfer stays parked and the
     * user can try again, because a typo is the common case and dropping the connection
     * would make them start over.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    boolean confirmTransferPin(long transferId, String pin);

    /**
     * Same as sendFilesOnSocket, but the socket is an L2CAP connection-oriented channel.
     *
     * The difference is not cosmetic. An RFCOMM socket is a byte stream the protocol can
     * be written to directly; an L2CAP channel carries a virtual socket that has to be
     * requested and accepted first, and a peer will not answer a single frame until it
     * has been. The daemon does that handshake here and nowhere else.
     *
     * Which one to open is decided by TarishPeer.psm, which the peer itself published.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    long sendFilesOnL2capSocket(String peerId, in ParcelFileDescriptor socket,
            in ParcelFileDescriptor[] files, in String[] names);

    /**
     * Hand back the socket asked for by ITarishCallback.onUpgradeNeeded.
     *
     * `socket` is a TCP connection to the peer over the network the app just joined,
     * already connected. Pass null to decline -- because the join failed, the permission
     * is missing, or the client would rather not. Declining is not an error and does not
     * end the transfer: it continues on the transport it is already on.
     *
     * A socket for a transfer that is no longer waiting for one is closed and ignored,
     * which is the right answer for a late reply to a transfer that has since timed out
     * or been cancelled.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    void provideUpgradeSocket(long transferId, in @nullable ParcelFileDescriptor socket);

    /**
     * Send to a Quick Share peer over the LAN, on a socket the DAEMON opens.
     *
     * TRY THIS FIRST for any Quick Share peer. Wi-Fi LAN is a bootstrap medium in this
     * protocol, not something a transfer upgrades to: a peer on the same subnet publishes
     * an address and port over mDNS and is reached by connecting to it, which is how a
     * stock implementation gets full speed to a Windows machine. Bluetooth is the answer
     * for a peer that is NOT on our network, and it runs at a fraction of the speed --
     * around 200 KB/s measured, against a LAN's tens of megabytes.
     *
     * Unlike the Bluetooth variants the caller opens no socket, because there is nothing
     * here the app is needed for: the address came from the daemon's own mDNS browser, and
     * the daemon holds the local-network grant that lets it connect. It is the same
     * division as everywhere else -- the app owns the radio, the daemon owns the protocol,
     * and a TCP connection on an already-joined network needs no radio.
     *
     * Returns 0 when there is no LAN route to this peer, or the connection failed. That is
     * the normal answer for a peer discovered only over BLE, and the caller should then
     * fall back to sendFilesOnSocket or sendFilesOnL2capSocket. It is deliberately not an
     * exception: having no LAN route is the expected case off-network, not an error.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    long sendFilesOnLan(String peerId, in ParcelFileDescriptor[] files, in String[] names);

    /**
     * The BLE service data to advertise so Quick Share senders can find this device.
     *
     * THE DAEMON ENCODES, THE APP RADIATES -- the mirror of reportBlePeer, and the same
     * reason. The advertisement's layout lives in libtarish_protocol with test vectors taken
     * from a real Pixel and a real Windows machine, so building it in Java would be a second
     * implementation of a format we already got right once, free to drift from the decoder.
     *
     * `bluetoothMac` is this device's Bluetooth Classic address, which goes INSIDE the
     * advertisement: a peer with no address can see us and not connect. The app has to
     * supply it because the daemon cannot reach Bluetooth at all. Pass it as
     * "XX:XX:XX:XX:XX:XX".
     *
     * Returns an empty array if the address is unusable or the device has no receive
     * identity yet, in which case do not advertise -- an advertisement without an address is
     * worse than none, since it puts a device in the sender's list that cannot be reached.
     *
     * The bytes go in an AdvertiseData service-data field under 16-bit UUID 0xFEF3. They
     * change if the device name changes, so ask again rather than caching across a restart.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    byte[] quickShareAdvertisement(String bluetoothMac);

    /**
     * Receive a Quick Share transfer on a socket the CALLER already accepted.
     *
     * The receiving counterpart to sendFilesOnSocket, and the same division: a peer with no
     * shared network arrives over Bluetooth, framework Bluetooth is unreachable from a
     * native service, so the app accepts the connection and the daemon runs the protocol.
     *
     * As on the send side this is one end of a socket PAIR rather than the Bluetooth socket
     * itself, because Android does not expose a BluetoothSocket's descriptor. The app pumps
     * between the two.
     *
     * Returns a transfer id, or 0 if it could not be started -- policy forbids receiving, or
     * the descriptor could not be taken. The offer prompt, the answer and the files then
     * follow the ordinary path: onTransferOffered, respondToOffer, getReceivedFiles.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    long receiveOnSocket(in ParcelFileDescriptor socket);

    /**
     * Hand back the Wi-Fi Direct group asked for by ITarishCallback.onGroupNeeded.
     *
     * THE RECEIVER HOSTS, which is why this exists at all: the side that receives
     * UPGRADE_PATH_REQUEST stands up the network and answers with UPGRADE_PATH_AVAILABLE.
     * Sending is the mirror -- there the peer hosts and we join, through provideUpgradeSocket.
     *
     * An empty `ssid` declines, which is an ordinary answer rather than an error: no Wi-Fi
     * Direct on the device, a driver that would not form a group, or a client that would
     * rather not. The transfer then continues over Bluetooth, slower.
     *
     * ANSWER EITHER WAY. The inbound transfer is parked waiting for this, and a client that
     * simply does not reply costs it the timeout before it carries on.
     *
     * The client tears the group down itself when the transfer ends -- it already learns
     * that from onTransferFinished, and a group left up holds the radio and keeps the
     * device on a network that exists for nobody.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    void provideWifiDirectGroup(long transferId, in TarishGroup group);

    /**
     * Forget this device's AirDrop identity and generate a fresh random one.
     *
     * The identity is a persisted random 12-hex handle (NOT the MAC, which the radio
     * randomises on every acquire). It exists so an Apple peer sees ONE stable device
     * across sessions instead of a new "ghost" tile every time the radio cycles.
     *
     * Resetting it is a privacy vs. continuity trade the user owns: it makes this device
     * unlinkable to peers that had it saved (good for privacy), at the cost that those
     * peers no longer recognise it and AirDrop to the same devices gets less seamless.
     * The old identity is withdrawn and the new one advertised immediately; the change
     * survives reboots. Intended for a "reset identity" control in settings.
     *
     * APPENDED LAST -- transaction codes are positional; a new method goes at the end so
     * an app built against an older interface keeps calling the right transaction.
     */
    void resetIdentity();

    /**
     * Version of tarishd itself (its crate version), for the app's About screen.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    String getDaemonVersion();

    /**
     * Version of the AWDL stack (tlink) the daemon is running: the shim it dlopened, read
     * from that library's optional `mosey_version` symbol. Returns "unknown" when the
     * loaded library does not export it -- an older pin, or Google's own libmosey.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    String getLinkVersion();

    /**
     * The Quick Share peers currently discovered over the LAN (mDNS on wlan0), each as
     * "endpointId|name|addr:port". This is the table sendFilesOnLan resolves against, so a
     * caller (e.g. tarishctl for automated testing) can see exactly what a LAN send would
     * reach without parsing rotating log lines. Empty off-network or before discovery.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    String[] getQuickShareLanPeers();

    /**
     * Report that a person has just authenticated to this device, opening a window during
     * which the VPN lockdown exemption is permitted.
     *
     * WHAT THIS DOES AND DOES NOT BUY. It changes exactly one thing: the priority of the
     * daemon's routing rule, from below Android's kill-switch to above it. It does not
     * enable sharing, make the device discoverable, or grant any network reach beyond the
     * link-local route that rule already points at. With no always-on VPN in lockdown mode
     * it changes nothing observable at all.
     *
     * The CALLER does the authenticating -- BiometricPrompt or the device credential -- for
     * the same reason the app owns BLE and Wi-Fi Direct: it is framework API a native
     * service cannot reach. That makes this a report, not a proof, and the trust boundary
     * is the caller's identity: the service is reachable only from our own app's SELinux
     * domain, keyed on package name AND platform signature (see sepolicy/tarish_app.te).
     *
     * durationSeconds is capped by the daemon (ten minutes). Passing false, or letting the
     * window lapse, demotes the rule back below the kill-switch.
     *
     * THREE INDEPENDENT THINGS CLOSE THE WINDOW, because the property outlives the process
     * that set it: the caller closing it, the daemon's own capped timer, and the daemon
     * clearing it unconditionally at startup -- so a crash mid-window becomes a closed
     * window once init restarts us, rather than an exemption nobody is left to withdraw.
     * The daemon does NOT watch for this client's death; the cap is what bounds that case.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    void setAuthenticated(boolean authenticated, int durationSeconds);

    /**
     * Answer a keep-unlocked challenge. The reply half of
     * ITarishCallback.onKeepUnlockedChallenge.
     *
     * Only the nonce from the most recent outstanding challenge is accepted, exactly once.
     * A stale, repeated, guessed or absent nonce is the same as no answer, and the exemption
     * is withdrawn on the daemon's own deadline.
     *
     * Answering does NOT open a window — only setAuthenticated does, and only after a real
     * authentication. This keeps an already-open one alive and can do nothing else.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    void keepUnlocked(long nonce);

    /**
     * Is a VPN kill-switch actually in force right now?
     *
     * THE APP CANNOT ANSWER THIS ITSELF, which is the whole reason the method exists.
     * Settings.Global.always_on_vpn_lockdown reads **null** while lockdown is in force --
     * measured on hardware -- because a VPN app can enter lockdown by another path. The only
     * honest test is whether the kernel holds a `prohibit` routing rule, and reading that
     * needs netlink, which an app does not get.
     *
     * Shipping without it was a real mistake that reached a device: the app locked itself and
     * told the person it was because of a VPN kill-switch, on a phone where "Block
     * connections without VPN" was switched off.
     *
     * Answered from a property that tarishd publishes, because tarishd is the process with
     * the netlink socket. FAILS CLOSED: unknown means true, so the cost of being wrong is one
     * authentication prompt rather than a missing exemption on a device that needs it.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    boolean isLockdownActive();

    /**
     * Report an Apple Continuity advertisement the app saw: the manufacturer data under
     * company id 0x004C, as scanned, with the address it came from and its RSSI.
     *
     * THIS IS HOW A PEER THAT LEFT GETS REMOVED IN SECONDS RATHER THAN AN HOUR. iOS
     * advertises AirDrop over mDNS with a 4500 s TTL and withdraws nothing when the
     * screen locks, AirDrop is switched off, or the phone walks away. The signal for all
     * three is on BLE: the Nearby Info message carries a bit that is set exactly while
     * the device will take an AirDrop, and a device that is gone stops advertising. Both
     * were measured on two iPhones; the table is in libtarish_protocol's `apple` module.
     *
     * THE APP OWNS THE RADIO; THE DAEMON OWNS THE DECODER -- the same split as
     * reportBlePeer, and the same reason. The app forwards the bytes; the daemon reads
     * the bit, counts the devices, and reacts: it probes every AirDrop peer at once (a
     * unicast mDNS question each), labels peers STATE_SCREEN_OFF when the count says
     * none is receptive, and drops a peer that stops answering.
     *
     * Forward a sighting when the address is new, when its bytes change, and otherwise
     * about once a second per address as a keep-alive; the daemon treats an address it
     * has not heard for a couple of seconds as gone. A random address rotates on every
     * state change, so it is a dedupe key within a session, never an identity.
     *
     * APPENDED LAST -- transaction codes are positional.
     */
    void reportAppleAdvertisement(String address, int rssi, in byte[] manufacturerData);
}
