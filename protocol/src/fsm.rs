//! The sharing state machines: what may happen next, and what must not.
//!
//! The frames in `crate::sharing` say what can be expressed. These say what is allowed
//! *when*, which is a separate question and the one that carries the security weight. A
//! peer that sends an introduction before the paired-key exchange, or a second
//! introduction after the first was accepted, or a file that was never announced, is not
//! confused -- there is no implementation that does those by accident. Each is a
//! deliberate reordering that a permissive receiver would act on.
//!
//! ```text
//! sender                                   receiver
//!   PairedKeyEncryption      ------------>
//!   PairedKeyResult          ------------>   all three, without waiting
//!   Introduction             ------------>
//!                                           (a human decides)
//!                            <------------  Response(ACCEPT | REJECT)
//!   file payloads            ------------>
//!
//! The sender does NOT wait between those three. It was written that way first and hung
//! against a real peer: the receiver had nothing to say until it knew what was on offer,
//! and we would not offer until it had spoken. The receiver is the side that waits,
//! because it is the side with a decision to make.
//! ```
//!
//! Sans-IO, like everything else here: events in, effects out, no sockets and no clock.
//! The caller performs the effects. That is what lets "a peer sent an introduction twice"
//! be a unit test rather than a thing to reproduce with two phones.
//!
//! **The user's decision is an event, never an assumption.** The receiving machine will
//! not send an acceptance on its own under any sequence of peer frames -- the only
//! transition out of `AwaitingUser` is `Event::UserAccepted` or `Event::UserRejected`.
//! That is the property the whole prompt exists for, so it is enforced by the shape of
//! the machine rather than by remembering to check.

use crate::sharing::{self, Frame, Introduction, PairedKeyResult, Status};
use std::fmt;

/// What happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A sharing frame arrived from the peer.
    Frame(Frame),
    /// The person approved the transfer.
    UserAccepted,
    /// The person refused it.
    UserRejected,
    /// Either side gave up locally.
    UserCancelled,
    /// Every announced payload has arrived (receiver) or been sent (sender).
    TransferComplete,
}

/// What the caller must do. Sending is bytes because the caller owns the channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Wrap this sharing frame in a BYTES payload and send it.
    Send(Vec<u8>),
    /// Show the person what is being offered and ask. The only thing that produces an
    /// acceptance is their answer coming back as an event.
    AskUser(Introduction),
    /// The peer accepted; begin sending files.
    BeginSending(Introduction),
    /// We accepted; begin accepting the announced payloads.
    BeginReceiving(Introduction),
    /// Finished cleanly.
    Done,
    /// Over, and why. The caller closes the connection.
    Failed(&'static str),
    /// The peer or the user cancelled.
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Exchanging identity claims.
    PairedKey,
    /// Receiver: waiting for the file list. Sender: waiting to send it.
    Introduction,
    /// Receiver only: a human is deciding. Nothing leaves this state on its own.
    AwaitingUser,
    /// Files are moving.
    Transferring,
    Done,
    Failed,
    Cancelled,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            State::PairedKey => "paired-key",
            State::Introduction => "introduction",
            State::AwaitingUser => "awaiting-user",
            State::Transferring => "transferring",
            State::Done => "done",
            State::Failed => "failed",
            State::Cancelled => "cancelled",
        };
        f.write_str(s)
    }
}

impl State {
    fn is_over(self) -> bool {
        matches!(self, State::Done | State::Failed | State::Cancelled)
    }
}

/// Receiving side.
pub struct Inbound {
    state: State,
    /// Whether we have sent our own paired-key frames yet.
    sent_paired_key: bool,
    seen_peer_result: bool,
    introduction: Option<Introduction>,
}

impl Default for Inbound {
    fn default() -> Self {
        Self::new()
    }
}

impl Inbound {
    pub fn new() -> Self {
        Self {
            state: State::PairedKey,
            sent_paired_key: false,
            seen_peer_result: false,
            introduction: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// What was offered, once an introduction has arrived.
    pub fn introduction(&self) -> Option<&Introduction> {
        self.introduction.as_ref()
    }

    /// Open the exchange by sending our identity claim.
    pub fn start(&mut self) -> Vec<Effect> {
        if self.sent_paired_key {
            return Vec::new();
        }
        self.sent_paired_key = true;
        match sharing::paired_key_encryption() {
            Ok(f) => vec![Effect::Send(f)],
            Err(_) => {
                self.state = State::Failed;
                vec![Effect::Failed("could not build the paired-key frame")]
            }
        }
    }

    pub fn on(&mut self, event: Event) -> Vec<Effect> {
        if self.state.is_over() {
            return Vec::new();
        }
        match event {
            Event::UserCancelled => {
                self.state = State::Cancelled;
                return vec![Effect::Send(sharing::cancel()), Effect::Cancelled];
            }
            Event::UserAccepted => {
                // ONLY from AwaitingUser. Accepting from any other state would mean a
                // decision about something the person was never shown.
                if self.state != State::AwaitingUser {
                    return self.fail("acceptance arrived before an offer");
                }
                self.state = State::Transferring;
                let intro = self.introduction.clone().unwrap_or_default();
                return vec![
                    Effect::Send(sharing::response(Status::Accept)),
                    Effect::BeginReceiving(intro),
                ];
            }
            Event::UserRejected => {
                if self.state != State::AwaitingUser {
                    return self.fail("rejection arrived before an offer");
                }
                self.state = State::Done;
                return vec![Effect::Send(sharing::response(Status::Reject)), Effect::Done];
            }
            Event::TransferComplete => {
                if self.state != State::Transferring {
                    return self.fail("transfer completed before it started");
                }
                self.state = State::Done;
                return vec![Effect::Done];
            }
            Event::Frame(frame) => self.on_frame(frame),
        }
    }

    fn on_frame(&mut self, frame: Frame) -> Vec<Effect> {
        match (self.state, frame) {
            (_, Frame::Cancel) => {
                self.state = State::Cancelled;
                vec![Effect::Cancelled]
            }

            // Their claim; answer with our verdict, which is always Unable.
            (State::PairedKey, Frame::PairedKeyEncryption { .. }) => {
                vec![Effect::Send(sharing::paired_key_result(
                    PairedKeyResult::Unable,
                ))]
            }
            (State::PairedKey, Frame::PairedKeyResult(_)) => {
                self.seen_peer_result = true;
                self.state = State::Introduction;
                Vec::new()
            }

            (State::Introduction, Frame::Introduction(intro)) => {
                // An introduction with nothing in it would put an empty prompt in front
                // of a person, who would then approve "nothing" and see a transfer that
                // never ends.
                if intro.files.is_empty() && intro.texts.is_empty() {
                    return self.fail("introduction announced no attachments");
                }
                self.introduction = Some(intro.clone());
                self.state = State::AwaitingUser;
                vec![Effect::AskUser(intro)]
            }

            // A SECOND introduction, after the person has already been shown the first.
            // Acting on it would swap what was approved for something else.
            (State::AwaitingUser | State::Transferring, Frame::Introduction(_)) => {
                self.fail("a second introduction arrived after the first")
            }

            // Late paired-key frames are noise, not an attack; ignore them rather than
            // dropping a transfer that is otherwise fine.
            (_, Frame::PairedKeyEncryption { .. }) | (_, Frame::PairedKeyResult(_)) => Vec::new(),

            (_, Frame::Unknown(_)) => Vec::new(),

            // A SENDER CONFIRMS THE ACCEPTANCE, and that is not an error.
            //
            // A receiver never acts on a Response -- it is the side that sends one -- so
            // this rejected it outright. But a stock Android sender answers our accept with
            // its own Response before it starts the payload, and killing the transfer for it
            // meant every inbound transfer from an Android device died seven milliseconds
            // after the person tapped Accept:
            //
            //     sharing refused: the peer answered an offer we never made
            //
            // Windows does not send one, which is why receiving from Windows worked and hid
            // this. Ignored rather than acted on: a receiver has nothing to do with it, and
            // the same reasoning as the late paired-key frames above applies -- unexpected
            // is not the same as hostile.
            (_, Frame::Response(_)) => Vec::new(),

            (state, frame) => {
                let _ = (state, frame);
                self.fail("frame arrived in a state that does not allow it")
            }
        }
    }

    fn fail(&mut self, why: &'static str) -> Vec<Effect> {
        self.state = State::Failed;
        vec![Effect::Failed(why)]
    }
}

/// Sending side.
pub struct Outbound {
    state: State,
    introduction: Introduction,
    sent_paired_key: bool,
}

impl Outbound {
    pub fn new(introduction: Introduction) -> Self {
        Self {
            state: State::PairedKey,
            introduction,
            sent_paired_key: false,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Open the exchange: identity claim, our verdict, and the file list, ALL AT ONCE.
    ///
    /// A sender does not wait for the receiver between these. It was written that way
    /// first -- send the paired key, wait for theirs, then answer, then introduce -- and
    /// against a real Windows peer it hung forever with the channel up and both sides
    /// healthy: the peer had nothing to say until it had been told what was on offer, and
    /// we would not offer until it had spoken. Neither side was wrong on the wire and
    /// nothing timed out.
    ///
    /// The receiver is the one that waits, because it is the one with a decision to make.
    pub fn start(&mut self) -> Vec<Effect> {
        if self.sent_paired_key {
            return Vec::new();
        }
        self.sent_paired_key = true;
        let pke = match sharing::paired_key_encryption() {
            Ok(f) => f,
            Err(_) => {
                self.state = State::Failed;
                return vec![Effect::Failed("could not build the paired-key frame")];
            }
        };
        self.state = State::Introduction;
        vec![
            Effect::Send(pke),
            Effect::Send(sharing::paired_key_result(PairedKeyResult::Unable)),
            Effect::Send(sharing::introduction(&self.introduction)),
        ]
    }

    pub fn on(&mut self, event: Event) -> Vec<Effect> {
        if self.state.is_over() {
            return Vec::new();
        }
        match event {
            Event::UserCancelled => {
                self.state = State::Cancelled;
                vec![Effect::Send(sharing::cancel()), Effect::Cancelled]
            }
            Event::TransferComplete => {
                if self.state != State::Transferring {
                    return self.fail("transfer completed before it started");
                }
                self.state = State::Done;
                vec![Effect::Done]
            }
            // A sender has no prompt of its own to answer.
            Event::UserAccepted | Event::UserRejected => {
                self.fail("a local decision arrived on the sending side")
            }
            Event::Frame(frame) => self.on_frame(frame),
        }
    }

    fn on_frame(&mut self, frame: Frame) -> Vec<Effect> {
        match (self.state, frame) {
            (_, Frame::Cancel) => {
                self.state = State::Cancelled;
                vec![Effect::Cancelled]
            }

            (State::Introduction, Frame::Response(Status::Accept)) => {
                self.state = State::Transferring;
                vec![Effect::BeginSending(self.introduction.clone())]
            }
            (State::Introduction, Frame::Response(_)) => {
                // A refusal is a normal answer, not a failure. Reporting it as an error
                // invites a retry that will be refused again.
                self.state = State::Done;
                vec![Effect::Done]
            }

            (_, Frame::PairedKeyEncryption { .. }) | (_, Frame::PairedKeyResult(_)) => Vec::new(),
            (_, Frame::Unknown(_)) => Vec::new(),

            (_, Frame::Introduction(_)) => {
                self.fail("the peer tried to introduce files on a connection we opened")
            }

            (state, frame) => {
                let _ = (state, frame);
                self.fail("frame arrived in a state that does not allow it")
            }
        }
    }

    fn fail(&mut self, why: &'static str) -> Vec<Effect> {
        self.state = State::Failed;
        vec![Effect::Failed(why)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sharing::{FileMetadata, FileType};

    fn intro() -> Introduction {
        Introduction {
            files: vec![FileMetadata {
                name: "a.jpg".into(),
                file_type: FileType::Image,
                payload_id: 7,
                size: 100,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn pke() -> Frame {
        Frame::PairedKeyEncryption {
            signed_data: vec![0; 72],
            secret_id_hash: vec![0; 6],
        }
    }

    /// A SENDER CONFIRMS THE ACCEPTANCE, and a receiver must not die on it.
    ///
    /// A stock Android sender answers our accept with its own Response before it starts the
    /// payload. This used to be fatal -- "the peer answered an offer we never made" -- so
    /// every inbound transfer from an Android device failed seven milliseconds after the
    /// person tapped Accept. Windows sends none, which is why receiving from Windows worked
    /// and hid it entirely.
    #[test]
    fn a_receiver_ignores_the_senders_own_response() {
        let mut r = Inbound::new();
        r.start();
        r.on(Event::Frame(pke()));
        r.on(Event::Frame(Frame::PairedKeyResult(PairedKeyResult::Unable)));
        r.on(Event::Frame(Frame::Introduction(intro())));
        r.on(Event::UserAccepted);
        assert_eq!(r.state(), State::Transferring);

        assert_eq!(
            r.on(Event::Frame(Frame::Response(Status::Accept))),
            vec![],
            "a sender's confirmation is not ours to act on, and not a reason to stop"
        );
        assert_eq!(r.state(), State::Transferring, "and it must not move us out of the transfer");
    }

    /// The happy path, receiving.
    #[test]
    fn a_receiver_walks_the_whole_exchange() {
        let mut r = Inbound::new();
        assert!(matches!(r.start()[..], [Effect::Send(_)]));

        assert!(matches!(r.on(Event::Frame(pke()))[..], [Effect::Send(_)]));
        assert_eq!(r.on(Event::Frame(Frame::PairedKeyResult(PairedKeyResult::Unable))), vec![]);
        assert_eq!(r.state(), State::Introduction);

        match &r.on(Event::Frame(Frame::Introduction(intro())))[..] {
            [Effect::AskUser(got)] => assert_eq!(got.files[0].name, "a.jpg"),
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(r.state(), State::AwaitingUser);

        match &r.on(Event::UserAccepted)[..] {
            [Effect::Send(_), Effect::BeginReceiving(got)] => assert_eq!(got.files.len(), 1),
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(r.state(), State::Transferring);
        assert_eq!(r.on(Event::TransferComplete), vec![Effect::Done]);
        assert_eq!(r.state(), State::Done);
    }

    /// The happy path, sending. All three frames go out at once.
    #[test]
    fn a_sender_walks_the_whole_exchange() {
        let mut s = Outbound::new(intro());
        assert!(
            matches!(s.start()[..], [Effect::Send(_), Effect::Send(_), Effect::Send(_)]),
            "sender must offer without waiting"
        );
        assert_eq!(s.state(), State::Introduction);
        assert!(matches!(
            s.on(Event::Frame(Frame::Response(Status::Accept)))[..],
            [Effect::BeginSending(_)]
        ));
        assert_eq!(s.state(), State::Transferring);
    }

    /// THE REGRESSION. A peer that says nothing until it has been told what is on offer
    /// must still receive the offer -- this hung forever against real Windows Quick
    /// Share, with the encrypted channel up and neither side wrong on the wire.
    #[test]
    fn a_sender_offers_without_the_peer_speaking_first() {
        let mut s = Outbound::new(intro());
        let effects = s.start();
        // The third frame is the introduction; without it the peer has no reason to
        // reply and both sides wait.
        assert_eq!(effects.len(), 3, "paired key, result, introduction");
        let intro_bytes = match &effects[2] {
            Effect::Send(b) => b.clone(),
            other => panic!("third effect should be the introduction: {other:?}"),
        };
        assert!(matches!(
            sharing::parse(&intro_bytes).unwrap(),
            Frame::Introduction(_)
        ));
    }

    /// THE property. No sequence of peer frames may produce an acceptance -- only a
    /// person can.
    #[test]
    fn nothing_a_peer_sends_can_accept_on_the_users_behalf() {
        let mut r = Inbound::new();
        r.start();
        r.on(Event::Frame(pke()));
        r.on(Event::Frame(Frame::PairedKeyResult(PairedKeyResult::Unable)));
        r.on(Event::Frame(Frame::Introduction(intro())));
        assert_eq!(r.state(), State::AwaitingUser);

        // Everything a peer could possibly say, repeatedly.
        for _ in 0..3 {
            for f in [
                pke(),
                Frame::PairedKeyResult(PairedKeyResult::Success),
                Frame::Response(Status::Accept),
                Frame::Unknown(9),
            ] {
                let effects = r.on(Event::Frame(f));
                assert!(
                    !effects.iter().any(|e| matches!(e, Effect::BeginReceiving(_))),
                    "a peer frame started the transfer"
                );
            }
            if r.state() != State::AwaitingUser {
                break; // it failed the connection instead, which is also fine
            }
        }
        assert_ne!(r.state(), State::Transferring);
    }

    /// A second introduction after the person was shown the first would swap what they
    /// approved for something else.
    #[test]
    fn a_second_introduction_is_refused() {
        let mut r = Inbound::new();
        r.start();
        r.on(Event::Frame(pke()));
        r.on(Event::Frame(Frame::PairedKeyResult(PairedKeyResult::Unable)));
        r.on(Event::Frame(Frame::Introduction(intro())));

        let mut other = intro();
        other.files[0].name = "something-else.exe".into();
        assert!(matches!(
            r.on(Event::Frame(Frame::Introduction(other)))[..],
            [Effect::Failed(_)]
        ));
        assert_eq!(r.state(), State::Failed);
    }

    /// An introduction before the paired-key exchange is out of order.
    #[test]
    fn an_introduction_before_the_paired_key_exchange_is_refused() {
        let mut r = Inbound::new();
        r.start();
        assert!(matches!(
            r.on(Event::Frame(Frame::Introduction(intro())))[..],
            [Effect::Failed(_)]
        ));
    }

    /// An empty offer would put a meaningless prompt in front of a person.
    #[test]
    fn an_empty_introduction_is_refused() {
        let mut r = Inbound::new();
        r.start();
        r.on(Event::Frame(pke()));
        r.on(Event::Frame(Frame::PairedKeyResult(PairedKeyResult::Unable)));
        assert!(matches!(
            r.on(Event::Frame(Frame::Introduction(Introduction::default())))[..],
            [Effect::Failed(_)]
        ));
    }

    #[test]
    fn a_rejection_answers_and_finishes() {
        let mut r = Inbound::new();
        r.start();
        r.on(Event::Frame(pke()));
        r.on(Event::Frame(Frame::PairedKeyResult(PairedKeyResult::Unable)));
        r.on(Event::Frame(Frame::Introduction(intro())));
        assert!(matches!(
            r.on(Event::UserRejected)[..],
            [Effect::Send(_), Effect::Done]
        ));
        assert_eq!(r.state(), State::Done);
    }

    /// A peer refusing is a normal answer, not an error to retry.
    #[test]
    fn a_refused_send_finishes_rather_than_failing() {
        let mut s = Outbound::new(intro());
        s.start();
        assert_eq!(
            s.on(Event::Frame(Frame::Response(Status::Reject))),
            vec![Effect::Done]
        );
        assert_eq!(s.state(), State::Done);
    }

    #[test]
    fn cancel_is_honoured_from_either_side_at_any_point() {
        for at in 0..3 {
            let mut r = Inbound::new();
            r.start();
            if at > 0 {
                r.on(Event::Frame(pke()));
            }
            if at > 1 {
                r.on(Event::Frame(Frame::PairedKeyResult(PairedKeyResult::Unable)));
            }
            assert_eq!(r.on(Event::Frame(Frame::Cancel)), vec![Effect::Cancelled]);
            assert_eq!(r.state(), State::Cancelled);
        }
    }

    /// Once it is over it stays over: no late frame may restart a finished exchange.
    #[test]
    fn a_finished_machine_ignores_everything_after() {
        let mut r = Inbound::new();
        r.start();
        r.on(Event::Frame(Frame::Cancel));
        assert_eq!(r.state(), State::Cancelled);
        for f in [pke(), Frame::Introduction(intro()), Frame::Cancel] {
            assert_eq!(r.on(Event::Frame(f)), vec![]);
        }
        assert_eq!(r.on(Event::UserAccepted), vec![]);
        assert_eq!(r.state(), State::Cancelled);
    }

    /// A sender must not accept a file list from the peer it dialled.
    #[test]
    fn a_sender_refuses_an_introduction_from_the_peer() {
        let mut s = Outbound::new(intro());
        s.start();
        // A sender never receives a file list; the peer it dialled is the receiver.
        assert!(matches!(
            s.on(Event::Frame(Frame::Introduction(intro())))[..],
            [Effect::Failed(_)]
        ));
    }

    /// A receiver IGNORES a response rather than refusing it, even an unprompted one.
    ///
    /// This asserted the opposite, and the opposite is what killed every inbound transfer
    /// from an Android device: a stock sender confirms our acceptance with its own Response,
    /// and treating that as fatal ended the transfer seven milliseconds after Accept. A
    /// receiver has nothing to do with a Response; that is a reason to skip it, not to die.
    #[test]
    fn a_receiver_ignores_a_response_it_did_not_expect() {
        let mut r = Inbound::new();
        r.start();
        assert_eq!(r.on(Event::Frame(Frame::Response(Status::Accept))), vec![]);
        assert_ne!(r.state(), State::Failed, "an unexpected response is not fatal");
    }

    #[test]
    fn unknown_frames_are_ignored_at_every_stage() {
        let mut r = Inbound::new();
        r.start();
        assert_eq!(r.on(Event::Frame(Frame::Unknown(42))), vec![]);
        r.on(Event::Frame(pke()));
        r.on(Event::Frame(Frame::PairedKeyResult(PairedKeyResult::Unable)));
        assert_eq!(r.on(Event::Frame(Frame::Unknown(43))), vec![]);
        assert_eq!(r.state(), State::Introduction);
    }
}
