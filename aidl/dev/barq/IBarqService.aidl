package dev.barq;

import dev.barq.IBarqCallback;
import dev.barq.BarqPeer;
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
     * Visibility is deliberately the DAEMON's state, not the app's, so closing
     * the app does not stop the device being reachable.
     */
    void setDiscoverable(boolean discoverable, int durationSeconds);

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
}
