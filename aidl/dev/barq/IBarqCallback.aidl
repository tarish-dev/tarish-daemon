package dev.barq;

import dev.barq.BarqPeer;

/** Events from barqd to a bound client. All calls are oneway: the daemon must
 *  never block on a UI process, which may be slow, frozen or about to die. */
oneway interface IBarqCallback {
    void onPeerFound(in BarqPeer peer);
    void onPeerLost(String peerId);

    /** An incoming transfer is being offered. Answer with respondToOffer(). */
    void onTransferOffered(long transferId, String peerId, in String[] names, long totalBytes);

    void onTransferProgress(long transferId, long bytesDone, long bytesTotal);

    /** status: 0 = complete, non-zero = failed or cancelled. */
    void onTransferFinished(long transferId, int status);
}
