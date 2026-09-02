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
}
