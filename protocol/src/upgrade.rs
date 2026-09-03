//! Bandwidth upgrade: moving a live connection onto a faster medium.
//!
//! This is what lets Quick Share work with **no shared network**. Two devices find each
//! other over BLE and open a slow control channel (Bluetooth, or BLE L2CAP). That is
//! enough to negotiate, and hopeless for a file. So one device stands up a Wi-Fi Direct
//! group or a hotspot, tells the other how to join, and the whole connection moves
//! across — same UKEY2 session, same sharing exchange, new socket.
//!
//! ```text
//! HOST                              JOINER
//!   UPGRADE_PATH_AVAILABLE  ------>          (old channel: here is the network)
//!                                            joins the network, opens a socket
//!         <------ CLIENT_INTRODUCTION        (NEW channel: it is me)
//!   CLIENT_INTRODUCTION_ACK ------>          (new channel)
//!         <------ LAST_WRITE_TO_PRIOR_CHANNEL   (old channel: I am done here)
//!   SAFE_TO_CLOSE_PRIOR_CHANNEL --->         (old channel)
//!                                            both close the old channel
//! ```
//!
//! **Which channel a frame goes on is part of the protocol, not an implementation
//! detail.** The introduction travels on the NEW socket -- that is how the host learns
//! which pending connection belongs to which endpoint -- while the teardown handshake
//! travels on the OLD one, because its whole purpose is to agree that the old one has
//! nothing left to carry. Sending either on the wrong socket produces a hang with no
//! error, so the effects here name the channel explicitly rather than leaving the caller
//! to infer it.
//!
//! **The ack is optional and its absence is not a failure.** `supports_client_introduction_ack`
//! in the offer says whether the host will answer the introduction. A joiner that waits
//! for an ack from a peer that never sends one waits forever, so the flag is read and
//! obeyed rather than assumed.
//!
//! Sans-IO: no sockets, no Wi-Fi, no clock. The caller joins the network and opens the
//! socket; this decides what to say and when. That is what makes an upgrade testable in
//! one process, which matters more here than anywhere else in the stack -- the
//! alternative is two phones, two radios and a hotspot.

use crate::protobuf::{self, Writer};
use std::fmt;

// BandwidthUpgradeNegotiationFrame
const BW_EVENT_TYPE: u32 = 1;
const BW_UPGRADE_PATH_INFO: u32 = 2;
const BW_CLIENT_INTRODUCTION: u32 = 3;
const BW_CLIENT_INTRODUCTION_ACK: u32 = 4;
const BW_SAFE_TO_CLOSE: u32 = 5;

// EventType
const E_UPGRADE_PATH_AVAILABLE: u64 = 1;
const E_LAST_WRITE_TO_PRIOR: u64 = 2;
const E_SAFE_TO_CLOSE_PRIOR: u64 = 3;
const E_CLIENT_INTRODUCTION: u64 = 4;
const E_UPGRADE_FAILURE: u64 = 5;
const E_CLIENT_INTRODUCTION_ACK: u64 = 6;

// UpgradePathInfo
const UP_MEDIUM: u32 = 1;
const UP_WIFI_HOTSPOT: u32 = 2;
const UP_WIFI_LAN: u32 = 3;
const UP_WIFI_DIRECT: u32 = 6;
const UP_SUPPORTS_DISABLING_ENCRYPTION: u32 = 7;
const UP_SUPPORTS_INTRODUCTION_ACK: u32 = 9;

// WifiHotspotCredentials
const HS_SSID: u32 = 1;
const HS_PASSWORD: u32 = 2;
const HS_PORT: u32 = 3;
const HS_GATEWAY: u32 = 4;
const HS_FREQUENCY: u32 = 5;

// WifiDirectCredentials
const WD_SSID: u32 = 1;
const WD_PASSWORD: u32 = 2;
const WD_PORT: u32 = 3;
const WD_FREQUENCY: u32 = 4;
const WD_GATEWAY: u32 = 5;

// WifiLanSocket
const LAN_IP: u32 = 1;
const LAN_PORT: u32 = 2;

// ClientIntroduction
const CI_ENDPOINT_ID: u32 = 1;
const CI_SUPPORTS_DISABLING_ENCRYPTION: u32 = 2;

// SafeToClosePriorChannel
const SC_STA_FREQUENCY: u32 = 1;

/// Mediums an upgrade can move onto. Same numbering as `frames::Medium`; repeated here
/// because the upgrade schema has its own enum and they are free to diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Medium {
    Unknown = 0,
    Bluetooth = 2,
    WifiHotspot = 3,
    Ble = 4,
    WifiLan = 5,
    WifiAware = 6,
    WifiDirect = 8,
    Awdl = 13,
}

impl Medium {
    fn from(v: u64) -> Self {
        match v {
            2 => Medium::Bluetooth,
            3 => Medium::WifiHotspot,
            4 => Medium::Ble,
            5 => Medium::WifiLan,
            6 => Medium::WifiAware,
            8 => Medium::WifiDirect,
            13 => Medium::Awdl,
            _ => Medium::Unknown,
        }
    }
}

/// How to reach the host on the new medium.
///
/// One type for hotspot and Wi-Fi Direct because the caller does the same thing with
/// both: join a network by SSID and passphrase, then open a TCP socket to a port. The
/// distinction that matters is carried by `medium`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WifiCredentials {
    pub ssid: String,
    pub password: String,
    pub port: i32,
    /// The schema's default is "0.0.0.0", which means "the network's own gateway" --
    /// whatever DHCP hands out on joining. Kept as given rather than resolved here.
    pub gateway: String,
    /// -1 when the host did not say. Not an error: it is a hint for radio tuning.
    pub frequency: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LanSocket {
    pub ip: Vec<u8>,
    pub port: i32,
}

/// The offer: which medium, and how to get onto it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradePath {
    pub medium: Medium,
    pub wifi: Option<WifiCredentials>,
    pub lan: Option<LanSocket>,
    /// Whether the host will answer a CLIENT_INTRODUCTION. A joiner that waits for an
    /// ack the host never sends waits forever.
    pub supports_introduction_ack: bool,
    pub supports_disabling_encryption: bool,
}

impl Default for UpgradePath {
    fn default() -> Self {
        Self {
            medium: Medium::Unknown,
            wifi: None,
            lan: None,
            // Assume NOT supported unless the offer says so. The safe default is the one
            // that does not block: a joiner that skips a wait it should have made simply
            // proceeds, whereas one that makes a wait it should have skipped hangs.
            supports_introduction_ack: false,
            supports_disabling_encryption: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// The host is offering a faster medium.
    PathAvailable(UpgradePath),
    /// The joiner announcing itself on the NEW channel.
    ClientIntroduction { endpoint_id: String },
    ClientIntroductionAck,
    /// The joiner has finished with the OLD channel.
    LastWriteToPrior,
    /// The host agrees the OLD channel can go.
    SafeToClosePrior { sta_frequency: i32 },
    /// The upgrade did not work. Not fatal to the connection -- see the FSM.
    Failure,
    Unknown(u64),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Protobuf(protobuf::Error),
    Malformed(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protobuf(e) => write!(f, "upgrade: {e}"),
            Error::Malformed(w) => write!(f, "upgrade: malformed ({w})"),
        }
    }
}

impl From<protobuf::Error> for Error {
    fn from(e: protobuf::Error) -> Self {
        Error::Protobuf(e)
    }
}

// ------------------------------------------------------------------ encoding ---

/// Wrap in a V1 offline frame of type BANDWIDTH_UPGRADE_NEGOTIATION.
fn wrap(body: &[u8]) -> Vec<u8> {
    crate::frames::bandwidth_upgrade(body)
}

fn encode_wifi(c: &WifiCredentials, direct: bool) -> Vec<u8> {
    let mut w = Writer::new();
    if direct {
        w.bytes(WD_SSID, c.ssid.as_bytes())
            .bytes(WD_PASSWORD, c.password.as_bytes())
            .varint(WD_PORT, c.port as i64 as u64)
            .varint(WD_FREQUENCY, c.frequency as i64 as u64)
            .bytes(WD_GATEWAY, c.gateway.as_bytes());
    } else {
        w.bytes(HS_SSID, c.ssid.as_bytes())
            .bytes(HS_PASSWORD, c.password.as_bytes())
            .varint(HS_PORT, c.port as i64 as u64)
            .bytes(HS_GATEWAY, c.gateway.as_bytes())
            .varint(HS_FREQUENCY, c.frequency as i64 as u64);
    }
    w.finish()
}

/// Build UPGRADE_PATH_AVAILABLE.
pub fn path_available(path: &UpgradePath) -> Vec<u8> {
    let mut info = Writer::new();
    info.varint(UP_MEDIUM, path.medium as u64);
    if let Some(c) = &path.wifi {
        let direct = path.medium == Medium::WifiDirect;
        let field = if direct { UP_WIFI_DIRECT } else { UP_WIFI_HOTSPOT };
        info.bytes(field, &encode_wifi(c, direct));
    }
    if let Some(l) = &path.lan {
        let mut s = Writer::new();
        s.bytes(LAN_IP, &l.ip).varint(LAN_PORT, l.port as i64 as u64);
        info.bytes(UP_WIFI_LAN, &s.finish());
    }
    info.varint(
        UP_SUPPORTS_DISABLING_ENCRYPTION,
        path.supports_disabling_encryption as u64,
    )
    .varint(
        UP_SUPPORTS_INTRODUCTION_ACK,
        path.supports_introduction_ack as u64,
    );

    let mut w = Writer::new();
    w.varint(BW_EVENT_TYPE, E_UPGRADE_PATH_AVAILABLE)
        .bytes(BW_UPGRADE_PATH_INFO, &info.finish());
    wrap(&w.finish())
}

/// Build CLIENT_INTRODUCTION. Goes on the NEW channel.
pub fn client_introduction(endpoint_id: &str) -> Vec<u8> {
    let mut ci = Writer::new();
    ci.bytes(CI_ENDPOINT_ID, endpoint_id.as_bytes())
        .varint(CI_SUPPORTS_DISABLING_ENCRYPTION, 0);
    let mut w = Writer::new();
    w.varint(BW_EVENT_TYPE, E_CLIENT_INTRODUCTION)
        .bytes(BW_CLIENT_INTRODUCTION, &ci.finish());
    wrap(&w.finish())
}

/// Build CLIENT_INTRODUCTION_ACK. Goes on the NEW channel.
pub fn client_introduction_ack() -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(BW_EVENT_TYPE, E_CLIENT_INTRODUCTION_ACK)
        .bytes(BW_CLIENT_INTRODUCTION_ACK, &[]);
    wrap(&w.finish())
}

/// Build LAST_WRITE_TO_PRIOR_CHANNEL. Goes on the OLD channel.
pub fn last_write_to_prior() -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(BW_EVENT_TYPE, E_LAST_WRITE_TO_PRIOR);
    wrap(&w.finish())
}

/// Build SAFE_TO_CLOSE_PRIOR_CHANNEL. Goes on the OLD channel.
pub fn safe_to_close_prior(sta_frequency: i32) -> Vec<u8> {
    let mut sc = Writer::new();
    sc.varint(SC_STA_FREQUENCY, sta_frequency as i64 as u64);
    let mut w = Writer::new();
    w.varint(BW_EVENT_TYPE, E_SAFE_TO_CLOSE_PRIOR)
        .bytes(BW_SAFE_TO_CLOSE, &sc.finish());
    wrap(&w.finish())
}

pub fn failure() -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(BW_EVENT_TYPE, E_UPGRADE_FAILURE);
    wrap(&w.finish())
}

// ------------------------------------------------------------------ decoding ---

/// Parse the BODY of a BANDWIDTH_UPGRADE_NEGOTIATION frame.
///
/// Takes the inner bytes, not a whole offline frame: `frames::parse` has already
/// dispatched on type and handed them over.
pub fn parse(body: &[u8]) -> Result<Frame, Error> {
    let event = protobuf::first_varint(body, BW_EVENT_TYPE)?
        .ok_or(Error::Malformed("no event type"))?;

    Ok(match event {
        E_UPGRADE_PATH_AVAILABLE => {
            let info = protobuf::first_bytes(body, BW_UPGRADE_PATH_INFO)?
                .ok_or(Error::Malformed("no upgrade path info"))?;
            Frame::PathAvailable(parse_path(info)?)
        }
        E_CLIENT_INTRODUCTION => {
            let ci = protobuf::first_bytes(body, BW_CLIENT_INTRODUCTION)?.unwrap_or(&[]);
            Frame::ClientIntroduction {
                endpoint_id: protobuf::first_bytes(ci, CI_ENDPOINT_ID)?
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .unwrap_or_default(),
            }
        }
        E_CLIENT_INTRODUCTION_ACK => Frame::ClientIntroductionAck,
        E_LAST_WRITE_TO_PRIOR => Frame::LastWriteToPrior,
        E_SAFE_TO_CLOSE_PRIOR => {
            let sc = protobuf::first_bytes(body, BW_SAFE_TO_CLOSE)?.unwrap_or(&[]);
            Frame::SafeToClosePrior {
                sta_frequency: protobuf::first_varint(sc, SC_STA_FREQUENCY)?.unwrap_or(0) as i64
                    as i32,
            }
        }
        E_UPGRADE_FAILURE => Frame::Failure,
        other => Frame::Unknown(other),
    })
}

fn parse_path(info: &[u8]) -> Result<UpgradePath, Error> {
    let medium = Medium::from(protobuf::first_varint(info, UP_MEDIUM)?.unwrap_or(0));

    let wifi = match protobuf::first_bytes(info, UP_WIFI_DIRECT)? {
        Some(c) => Some(parse_wifi(c, true)?),
        None => match protobuf::first_bytes(info, UP_WIFI_HOTSPOT)? {
            Some(c) => Some(parse_wifi(c, false)?),
            None => None,
        },
    };

    let lan = match protobuf::first_bytes(info, UP_WIFI_LAN)? {
        Some(s) => Some(LanSocket {
            ip: protobuf::first_bytes(s, LAN_IP)?.unwrap_or(&[]).to_vec(),
            port: protobuf::first_varint(s, LAN_PORT)?.unwrap_or(0) as i64 as i32,
        }),
        None => None,
    };

    Ok(UpgradePath {
        medium,
        wifi,
        lan,
        supports_introduction_ack: protobuf::first_varint(info, UP_SUPPORTS_INTRODUCTION_ACK)?
            .unwrap_or(0)
            != 0,
        supports_disabling_encryption: protobuf::first_varint(
            info,
            UP_SUPPORTS_DISABLING_ENCRYPTION,
        )?
        .unwrap_or(0)
            != 0,
    })
}

fn parse_wifi(b: &[u8], direct: bool) -> Result<WifiCredentials, Error> {
    let (ssid, pw, port, gw, freq) = if direct {
        (WD_SSID, WD_PASSWORD, WD_PORT, WD_GATEWAY, WD_FREQUENCY)
    } else {
        (HS_SSID, HS_PASSWORD, HS_PORT, HS_GATEWAY, HS_FREQUENCY)
    };
    Ok(WifiCredentials {
        ssid: protobuf::first_bytes(b, ssid)?
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default(),
        password: protobuf::first_bytes(b, pw)?
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default(),
        port: protobuf::first_varint(b, port)?.unwrap_or(0) as i64 as i32,
        // The schema default, which means "whatever DHCP gives you on joining".
        gateway: protobuf::first_bytes(b, gw)?
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_else(|| "0.0.0.0".into()),
        // -1 is the schema default and means "not stated", which is not the same as 0.
        frequency: protobuf::first_varint(b, freq)
            .ok()
            .flatten()
            .map(|v| v as i64 as i32)
            .unwrap_or(-1),
    })
}

// ----------------------------------------------------------------------- fsm ---

/// Which socket an effect belongs on. Getting this wrong hangs with no error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Old,
    New,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Send(Channel, Vec<u8>),
    /// Join this network and open a socket to it, then report `Event::Connected`.
    Join(UpgradePath),
    /// The old channel has nothing left to carry.
    CloseOld,
    /// Everything now runs on the new socket.
    Upgraded,
    /// The upgrade did not happen. The CONNECTION IS STILL FINE -- carry on where you
    /// were. An upgrade is an optimisation, and treating its failure as a connection
    /// failure would turn a slow transfer into no transfer.
    Abandoned(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    /// Host: offered, waiting for the joiner to appear on the new socket.
    Offered,
    /// Joiner: told to join, waiting for the caller's socket.
    Joining,
    /// Joiner: introduced itself, waiting for the ack.
    Introduced,
    /// Agreeing the old channel can close.
    Draining,
    Upgraded,
    Abandoned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A parsed upgrade frame, and which socket it arrived on.
    Frame(Channel, Frame),
    /// The caller joined the network and has a socket.
    Connected,
    /// The caller could not join.
    JoinFailed,
}

/// The side that stands up the new medium and offers it.
pub struct Host {
    state: State,
    path: UpgradePath,
    sta_frequency: i32,
}

impl Host {
    pub fn new(path: UpgradePath, sta_frequency: i32) -> Self {
        Self {
            state: State::Idle,
            path,
            sta_frequency,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Offer the path. Goes on the OLD channel, which is the only one that exists yet.
    pub fn start(&mut self) -> Vec<Effect> {
        self.state = State::Offered;
        vec![Effect::Send(Channel::Old, path_available(&self.path))]
    }

    pub fn on(&mut self, event: Event) -> Vec<Effect> {
        if matches!(self.state, State::Upgraded | State::Abandoned) {
            return Vec::new();
        }
        match event {
            Event::Frame(Channel::New, Frame::ClientIntroduction { .. }) => {
                // The joiner arrived. Answer only if we said we would -- a peer that was
                // told no ack is coming is not waiting for one, and sending it anyway is
                // an unexpected frame on a channel it is about to reuse.
                self.state = State::Draining;
                if self.path.supports_introduction_ack {
                    vec![Effect::Send(Channel::New, client_introduction_ack())]
                } else {
                    Vec::new()
                }
            }
            Event::Frame(Channel::Old, Frame::LastWriteToPrior) => {
                self.state = State::Upgraded;
                vec![
                    Effect::Send(Channel::Old, safe_to_close_prior(self.sta_frequency)),
                    Effect::CloseOld,
                    Effect::Upgraded,
                ]
            }
            Event::Frame(_, Frame::Failure) => self.abandon("the peer reported an upgrade failure"),
            Event::JoinFailed => self.abandon("could not join"),
            _ => Vec::new(),
        }
    }

    fn abandon(&mut self, why: &'static str) -> Vec<Effect> {
        self.state = State::Abandoned;
        vec![Effect::Abandoned(why)]
    }
}

/// The side that takes the offer and moves across.
pub struct Joiner {
    state: State,
    endpoint_id: String,
    path: Option<UpgradePath>,
}

impl Joiner {
    pub fn new(endpoint_id: &str) -> Self {
        Self {
            state: State::Idle,
            endpoint_id: endpoint_id.to_string(),
            path: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The path we were offered, once one has arrived.
    pub fn path(&self) -> Option<&UpgradePath> {
        self.path.as_ref()
    }

    pub fn on(&mut self, event: Event) -> Vec<Effect> {
        if matches!(self.state, State::Upgraded | State::Abandoned) {
            return Vec::new();
        }
        match event {
            Event::Frame(Channel::Old, Frame::PathAvailable(path)) => {
                if path.wifi.is_none() && path.lan.is_none() {
                    return self.abandon("the offer carried no way to reach the host");
                }
                self.state = State::Joining;
                self.path = Some(path.clone());
                vec![Effect::Join(path)]
            }
            Event::Connected => {
                if self.state != State::Joining {
                    return self.abandon("connected without an offer");
                }
                let ack = self
                    .path
                    .as_ref()
                    .map(|p| p.supports_introduction_ack)
                    .unwrap_or(false);
                let mut out = vec![Effect::Send(
                    Channel::New,
                    client_introduction(&self.endpoint_id),
                )];
                if ack {
                    self.state = State::Introduced;
                } else {
                    // No ack is coming, so do not wait for one. Move straight to draining
                    // the old channel, or this hangs forever against a peer that told us
                    // exactly what it would do.
                    self.state = State::Draining;
                    out.push(Effect::Send(Channel::Old, last_write_to_prior()));
                }
                out
            }
            Event::Frame(Channel::New, Frame::ClientIntroductionAck) => {
                if self.state != State::Introduced {
                    return Vec::new();
                }
                self.state = State::Draining;
                vec![Effect::Send(Channel::Old, last_write_to_prior())]
            }
            Event::Frame(Channel::Old, Frame::SafeToClosePrior { .. }) => {
                self.state = State::Upgraded;
                vec![Effect::CloseOld, Effect::Upgraded]
            }
            Event::JoinFailed => {
                // Tell the host so it can stop waiting and tear down the network it
                // stood up, rather than leaving a hotspot running for nobody.
                self.state = State::Abandoned;
                vec![
                    Effect::Send(Channel::Old, failure()),
                    Effect::Abandoned("could not join the offered network"),
                ]
            }
            Event::Frame(_, Frame::Failure) => self.abandon("the peer reported an upgrade failure"),
            _ => Vec::new(),
        }
    }

    fn abandon(&mut self, why: &'static str) -> Vec<Effect> {
        self.state = State::Abandoned;
        vec![Effect::Abandoned(why)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hotspot() -> UpgradePath {
        UpgradePath {
            medium: Medium::WifiHotspot,
            wifi: Some(WifiCredentials {
                ssid: "DIRECT-xy-Barq".into(),
                password: "hunter2hunter2".into(),
                port: 45123,
                gateway: "192.168.49.1".into(),
                frequency: 5180,
            }),
            lan: None,
            supports_introduction_ack: true,
            supports_disabling_encryption: false,
        }
    }

    /// Drive both sides against each other, moving frames between the two channels.
    #[test]
    fn a_whole_upgrade_completes_on_both_sides() {
        let mut host = Host::new(hotspot(), 2437);
        let mut joiner = Joiner::new("ABCD");

        // Host offers on the old channel.
        let offer = match &host.start()[..] {
            [Effect::Send(Channel::Old, bytes)] => bytes.clone(),
            other => panic!("unexpected: {other:?}"),
        };

        // Joiner reads it and is told to join.
        let body = crate::frames::upgrade_body(&offer).unwrap();
        let joined = match &joiner.on(Event::Frame(Channel::Old, parse(&body).unwrap()))[..] {
            [Effect::Join(p)] => p.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(joined.wifi.as_ref().unwrap().ssid, "DIRECT-xy-Barq");
        assert_eq!(joined.wifi.as_ref().unwrap().port, 45123);

        // Caller joins and reports back; joiner introduces itself on the NEW channel.
        let intro = match &joiner.on(Event::Connected)[..] {
            [Effect::Send(Channel::New, bytes)] => bytes.clone(),
            other => panic!("unexpected: {other:?}"),
        };

        // Host receives it on the new channel and acks.
        let body = crate::frames::upgrade_body(&intro).unwrap();
        let ack = match &host.on(Event::Frame(Channel::New, parse(&body).unwrap()))[..] {
            [Effect::Send(Channel::New, bytes)] => bytes.clone(),
            other => panic!("unexpected: {other:?}"),
        };

        // Joiner gets the ack, says it is done with the old channel.
        let body = crate::frames::upgrade_body(&ack).unwrap();
        let last = match &joiner.on(Event::Frame(Channel::New, parse(&body).unwrap()))[..] {
            [Effect::Send(Channel::Old, bytes)] => bytes.clone(),
            other => panic!("unexpected: {other:?}"),
        };

        // Host agrees and closes.
        let body = crate::frames::upgrade_body(&last).unwrap();
        let safe = match &host.on(Event::Frame(Channel::Old, parse(&body).unwrap()))[..] {
            [Effect::Send(Channel::Old, bytes), Effect::CloseOld, Effect::Upgraded] => bytes.clone(),
            other => panic!("unexpected: {other:?}"),
        };
        assert_eq!(host.state(), State::Upgraded);

        // Joiner closes too.
        let body = crate::frames::upgrade_body(&safe).unwrap();
        assert_eq!(
            joiner.on(Event::Frame(Channel::Old, parse(&body).unwrap())),
            vec![Effect::CloseOld, Effect::Upgraded]
        );
        assert_eq!(joiner.state(), State::Upgraded);
    }

    /// A host that says it will not ack must not be waited on.
    #[test]
    fn without_an_ack_the_joiner_does_not_wait_for_one() {
        let mut path = hotspot();
        path.supports_introduction_ack = false;
        let mut joiner = Joiner::new("ABCD");
        joiner.on(Event::Frame(Channel::Old, Frame::PathAvailable(path)));

        match &joiner.on(Event::Connected)[..] {
            [Effect::Send(Channel::New, _), Effect::Send(Channel::Old, _)] => {}
            other => panic!("should introduce and drain in one step: {other:?}"),
        }
        assert_eq!(joiner.state(), State::Draining);
    }

    /// And a host that said it would not ack must not send one.
    #[test]
    fn a_host_that_promised_no_ack_sends_none() {
        let mut path = hotspot();
        path.supports_introduction_ack = false;
        let mut host = Host::new(path, 2437);
        host.start();
        assert_eq!(
            host.on(Event::Frame(
                Channel::New,
                Frame::ClientIntroduction {
                    endpoint_id: "ABCD".into()
                }
            )),
            vec![]
        );
        assert_eq!(host.state(), State::Draining);
    }

    /// A failed upgrade leaves the CONNECTION alive. It is an optimisation.
    #[test]
    fn a_failed_join_abandons_the_upgrade_not_the_connection() {
        let mut joiner = Joiner::new("ABCD");
        joiner.on(Event::Frame(Channel::Old, Frame::PathAvailable(hotspot())));
        match &joiner.on(Event::JoinFailed)[..] {
            [Effect::Send(Channel::Old, _), Effect::Abandoned(_)] => {}
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(joiner.state(), State::Abandoned);
    }

    /// The host must hear about it, or it leaves a hotspot up for a peer that never comes.
    #[test]
    fn the_host_abandons_on_a_reported_failure() {
        let mut host = Host::new(hotspot(), 2437);
        host.start();
        assert!(matches!(
            host.on(Event::Frame(Channel::Old, Frame::Failure))[..],
            [Effect::Abandoned(_)]
        ));
    }

    /// An offer with no credentials is not an offer.
    #[test]
    fn an_empty_offer_is_refused() {
        let mut joiner = Joiner::new("ABCD");
        let empty = UpgradePath {
            medium: Medium::WifiHotspot,
            ..Default::default()
        };
        assert!(matches!(
            joiner.on(Event::Frame(Channel::Old, Frame::PathAvailable(empty)))[..],
            [Effect::Abandoned(_)]
        ));
    }

    #[test]
    fn hotspot_credentials_round_trip() {
        let path = hotspot();
        let body = crate::frames::upgrade_body(&path_available(&path)).unwrap();
        match parse(&body).unwrap() {
            Frame::PathAvailable(got) => assert_eq!(got, path),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn wifi_direct_credentials_round_trip() {
        let mut path = hotspot();
        path.medium = Medium::WifiDirect;
        let body = crate::frames::upgrade_body(&path_available(&path)).unwrap();
        match parse(&body).unwrap() {
            Frame::PathAvailable(got) => assert_eq!(got, path),
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// -1 is the schema default for frequency and means "not stated". It must survive as
    /// -1 rather than becoming 0 or a huge positive number, because 0 is a real value.
    #[test]
    fn an_unstated_frequency_stays_minus_one() {
        let mut path = hotspot();
        path.wifi.as_mut().unwrap().frequency = -1;
        let body = crate::frames::upgrade_body(&path_available(&path)).unwrap();
        match parse(&body).unwrap() {
            Frame::PathAvailable(got) => assert_eq!(got.wifi.unwrap().frequency, -1),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn the_other_events_round_trip() {
        let cases: Vec<(Vec<u8>, Frame)> = vec![
            (
                client_introduction("WXYZ"),
                Frame::ClientIntroduction {
                    endpoint_id: "WXYZ".into(),
                },
            ),
            (client_introduction_ack(), Frame::ClientIntroductionAck),
            (last_write_to_prior(), Frame::LastWriteToPrior),
            (
                safe_to_close_prior(5180),
                Frame::SafeToClosePrior {
                    sta_frequency: 5180,
                },
            ),
            (failure(), Frame::Failure),
        ];
        for (wire, want) in cases {
            let body = crate::frames::upgrade_body(&wire).unwrap();
            assert_eq!(parse(&body).unwrap(), want);
        }
    }

    #[test]
    fn garbage_and_truncation_do_not_panic() {
        let full = crate::frames::upgrade_body(&path_available(&hotspot())).unwrap();
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]);
        }
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 41 + 3) as u8).collect();
            let _ = parse(&junk);
        }
    }
}
