package dev.barq;

import dev.barq.IBarqCallback;
import dev.barq.BarqPeer;
import dev.barq.BarqPolicy;
import dev.barq.BarqStatus;

/**
 * The contract between barqd and its clients.
 *
 * It lives with the DAEMON because the daemon is the server: it defines the
 * protocol, and a client is written against it. The app repo consumes this file
 * rather than declaring its own copy, so the two cannot drift apart silently.
 *
 * Everything expensive — holding the AWDL link, discovery, mDNS, the transfer
 * itself — happens in barqd. A client is expected to be an ordinary app that is
 * NOT running most of the time: it binds when the user is looking at it, and
 * receives nothing when it is closed. That is the whole reason for the split, so
 * no method here should require the client to stay alive.
 */
interface IBarqService {
    /** Current transport state: link up, channel, country, peer count. */
    BarqStatus getStatus();

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
     * on, or 0 if it is not associated. It is passed HERE rather than through its
     * own call so there is no window where the daemon knows it should bring the
     * radio up but not yet which band is safe.
     *
     * The client is the only component that can see this. Both daemons are native
     * and have no framework access, and nothing exposes the association frequency
     * as a file either daemon can read.
     */
    void setActive(boolean active, int staFrequencyMhz);

    /** Peers currently known. Fresh as of the last discovery round. */
    BarqPeer[] getPeers();


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
    void registerCallback(IBarqCallback cb);
    void unregisterCallback(IBarqCallback cb);

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

    /**
     * Install the policy this device is to enforce.
     *
     * ENFORCEMENT LIVES HERE, NOT IN THE APP. barqsharingd is what advertises, browses,
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
    void setPolicy(in BarqPolicy policy);

    /** What the daemon is currently enforcing, for the settings screen to render. */
    BarqPolicy getPolicy();

    /**
     * Change the advertised name, persisting it across reboots.
     *
     * The app cannot write this itself: the name lives in `persist.barq.name`, and
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
     * rather than decoding it, because the decoder lives in libbarq_protocol with test
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
}
