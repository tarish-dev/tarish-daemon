package dev.tarish;

/**
 * What this device is permitted to do, per protocol and per direction.
 *
 * One type carries BOTH sources of policy: what the user chose in the app, and what an
 * administrator pinned through managed configuration. The admin value always wins, and
 * the matching `*Managed` flag says so — the app shows a pinned control disabled and
 * labelled rather than hiding it, because a control that silently refuses to move reads
 * as a broken app rather than as an enforced policy.
 *
 * Modes are a single value per protocol rather than a pair of booleans. An admin console
 * renders one dropdown from a choice field, and two booleans per protocol would invite
 * the combination that means nothing. The APP still draws two switches, because per
 * direction is how a person thinks about it; the mapping is in one place.
 */
// The Rust backend derives nothing by default, and the daemon holds this behind a
// Mutex and hands copies out of getPolicy.
@RustDerive(Clone=true, PartialEq=true)
parcelable TarishPolicy {
    /** One of ITarishService.MODE_*. */
    int airdrop;
    /** One of ITarishService.MODE_*. */
    int quickshare;
    /** Ask before accepting an incoming transfer. Defaults on; an admin may turn it off. */
    boolean requireConfirmation;
    /** What peers see. Empty means fall back to the device model. */
    String deviceName;

    /** Pinned by an administrator; the user cannot change it. */
    boolean airdropManaged;
    boolean quickshareManaged;
    boolean requireConfirmationManaged;
    boolean deviceNameManaged;

    /**
     * Whether the person sending must type the PIN shown on the receiving device before
     * anything is sent.
     *
     * On by default. Off is a real choice -- the PIN costs a step on every transfer, and
     * someone handing a file to a device in front of them may not want it -- but it is
     * the only check that the peer we negotiated with is the one in the room, so turning
     * it off is a decision rather than a default.
     *
     * Quick Share only. AirDrop has no equivalent: its confirmation is on the receiving
     * device, which is a different question.
     *
     * APPENDED LAST, and any future field must be too: parcelable fields are read
     * positionally, so inserting one above this silently shifts every field after it.
     */
    boolean requirePin;

    boolean requirePinManaged;
}
