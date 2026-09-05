package dev.barq;

import dev.barq.BarqPeer;

/** Events from barqd to a bound client. All calls are oneway: the daemon must
 *  never block on a UI process, which may be slow, frozen or about to die. */
oneway interface IBarqCallback {
    void onPeerFound(in BarqPeer peer);
    void onPeerLost(String peerId);

    /**
     * An incoming transfer is being offered. Answer with respondToOffer().
     *
     * `protocol` is one of IBarqService.PROTOCOL_*. The prompt names it, because
     * "someone wants to send you a file" is a different decision depending on whether
     * it arrived over AirDrop or Quick Share, and the sender's name alone does not say.
     */
    void onTransferOffered(long transferId, String peerId, in String[] names,
            long totalBytes, int protocol);

    void onTransferProgress(long transferId, long bytesDone, long bytesTotal);

    /** status: 0 = complete, non-zero = failed or cancelled. */
    /**
     * A transfer ended.
     *
     * status is 0 on success, -1 on failure, and -2 when the person on the other device
     * declined. Declined is separate on purpose: it is a normal answer rather than an
     * error, and reporting it as "could not send" invites a retry that will be refused
     * again.
     */
    void onTransferFinished(long transferId, int status);

    /**
     * Ask the person sending to type the PIN shown on the RECEIVING device.
     *
     * **The PIN itself is deliberately not in this call.** Both ends derive the same
     * four digits from the UKEY2 auth string, so a sender that displayed its own copy
     * would let someone confirm a transfer without ever looking at the other screen --
     * which is the one thing the PIN exists to prevent. The daemon keeps the value and
     * checks what the user typed, so it never crosses this interface in either
     * direction.
     *
     * Arrives after the introduction has gone out, because that is when the receiver
     * puts its PIN on screen. Answer with IBarqService.confirmTransferPin; nothing is
     * sent until it matches.
     *
     * APPENDED LAST, and any future method must be too: the Rust and Java stubs map
     * transaction codes by position, so inserting a method above this one silently
     * renumbers every method after it.
     */
    void onTransferPinRequired(long transferId);
}
