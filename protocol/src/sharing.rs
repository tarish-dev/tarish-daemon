//! Nearby Sharing — the layer that says what is being sent and whether it is wanted.
//!
//! These frames ride INSIDE `BYTES` payloads of the offline frames in `crate::frames`,
//! which is why they are a separate module with its own `Frame` type. The nesting is
//! genuinely three deep and worth stating once:
//!
//! ```text
//! [4-byte length]  ->  OfflineFrame  ->  PayloadTransfer(BYTES)  ->  sharing::Frame
//! ```
//!
//! The exchange, once the connection is up and encrypted:
//!
//! ```text
//! both  -> PairedKeyEncryption   identity claim, or random fill if we have no identity
//! both  -> PairedKeyResult       UNABLE, in our case
//! sender-> Introduction          the file list
//! recv  -> Response              ACCEPT or REJECT
//!         (files then flow as FILE payloads)
//! ```
//!
//! **We have no certificate store, and that is a deliberate position rather than a gap.**
//! A stock Quick Share sender proves it belongs to one of your contacts by signing the
//! receiver's UKEY2 token with a private key rooted in a Google account, and sending a
//! hash of the certificate's secret id alongside. Barq has no Google account by design,
//! so it cannot produce either value and does not want to. Filling both fields with
//! random bytes of the right length is what NearDrop does and what real Android peers
//! tolerate: the peer looks for a matching certificate, finds none, falls through to its
//! "visible to everyone" path, and the transfer proceeds with the user approving it by
//! hand. That is the correct outcome for an account-free device -- it is *anonymous*, not
//! *authenticated*, and the human approving the prompt is the authentication.

use crate::protobuf::{self, Field, Reader, Writer};
use std::fmt;

// Frame
const F_VERSION: u32 = 1;
const F_V1: u32 = 2;
const VERSION_V1: u64 = 1;

// V1Frame
const V1_TYPE: u32 = 1;
const V1_INTRODUCTION: u32 = 2;
const V1_RESPONSE: u32 = 3;
const V1_PAIRED_KEY_ENCRYPTION: u32 = 4;
const V1_PAIRED_KEY_RESULT: u32 = 5;

// V1Frame.FrameType
const T_INTRODUCTION: u64 = 1;
const T_RESPONSE: u64 = 2;
const T_PAIRED_KEY_ENCRYPTION: u64 = 3;
const T_PAIRED_KEY_RESULT: u64 = 4;
const T_CANCEL: u64 = 6;

// FileMetadata
const FM_NAME: u32 = 1;
const FM_TYPE: u32 = 2;
const FM_PAYLOAD_ID: u32 = 3;
const FM_SIZE: u32 = 4;
const FM_MIME_TYPE: u32 = 5;
const FM_ID: u32 = 6;
const FM_PARENT_FOLDER: u32 = 7;
const FM_ATTACHMENT_HASH: u32 = 8;
const FM_IS_SENSITIVE: u32 = 9;

// TextMetadata
const TM_TITLE: u32 = 2;
const TM_TYPE: u32 = 3;
const TM_PAYLOAD_ID: u32 = 4;
const TM_SIZE: u32 = 5;
const TM_ID: u32 = 6;

// IntroductionFrame
const IN_FILE_METADATA: u32 = 1;
const IN_TEXT_METADATA: u32 = 2;
const IN_START_TRANSFER: u32 = 6;
const IN_USE_CASE: u32 = 8;

/// `SharingUseCase.NEARBY_SHARE`. The alternative is REMOTE_COPY, which is a different
/// product; UNKNOWN (the proto default) is what a receiver sees when the field is absent.
const USE_CASE_NEARBY_SHARE: u64 = 1;

// ConnectionResponseFrame (the SHARING one -- not the offline frame of the same name)
const RS_STATUS: u32 = 1;

// PairedKeyEncryptionFrame
const PKE_SIGNED_DATA: u32 = 1;
const PKE_SECRET_ID_HASH: u32 = 2;

// PairedKeyResultFrame
const PKR_STATUS: u32 = 1;

/// Fill lengths for an identity we do not have.
///
/// Six and seventy-two are NearDrop's numbers, field-proven against stock Quick Share.
/// They are not arbitrary-looking for no reason: they are the plausible lengths of a
/// truncated secret-id HMAC and of a signature, so a peer's parser sees nothing odd
/// before it gets as far as failing to match a certificate.
pub const SECRET_ID_HASH_LEN: usize = 6;
pub const SIGNED_DATA_LEN: usize = 72;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Unknown = 0,
    Image = 1,
    Video = 2,
    AndroidApp = 3,
    Audio = 4,
    Document = 5,
    ContactCard = 6,
}

impl FileType {
    fn from(v: u64) -> Self {
        match v {
            1 => FileType::Image,
            2 => FileType::Video,
            3 => FileType::AndroidApp,
            4 => FileType::Audio,
            5 => FileType::Document,
            6 => FileType::ContactCard,
            _ => FileType::Unknown,
        }
    }

    /// Best guess from a MIME type. Advisory only -- it picks the icon the peer shows,
    /// and getting it wrong costs a wrong icon, never a failed transfer.
    pub fn of_mime(mime: &str) -> Self {
        match mime.split('/').next().unwrap_or("") {
            "image" => FileType::Image,
            "video" => FileType::Video,
            "audio" => FileType::Audio,
            _ => {
                if mime == "application/vnd.android.package-archive" {
                    FileType::AndroidApp
                } else if mime.starts_with("text/") || mime == "application/pdf" {
                    FileType::Document
                } else {
                    FileType::Unknown
                }
            }
        }
    }
}

/// How the receiver answered an introduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Unknown = 0,
    Accept = 1,
    Reject = 2,
    NotEnoughSpace = 3,
    UnsupportedAttachmentType = 4,
    TimedOut = 5,
}

impl Status {
    fn from(v: u64) -> Self {
        match v {
            1 => Status::Accept,
            2 => Status::Reject,
            3 => Status::NotEnoughSpace,
            4 => Status::UnsupportedAttachmentType,
            5 => Status::TimedOut,
            _ => Status::Unknown,
        }
    }
}

/// Outcome of the paired-key exchange. We always send `Unable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairedKeyResult {
    Unknown = 0,
    Success = 1,
    Fail = 2,
    Unable = 3,
}

impl PairedKeyResult {
    fn from(v: u64) -> Self {
        match v {
            1 => PairedKeyResult::Success,
            2 => PairedKeyResult::Fail,
            3 => PairedKeyResult::Unable,
            _ => PairedKeyResult::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    pub name: String,
    pub file_type: FileType,
    /// The id of the FILE payload that will carry the bytes. This is the join between
    /// the introduction and the transfer, so it must match exactly.
    pub payload_id: i64,
    pub size: i64,
    pub mime_type: String,
    /// Attachment id, distinct from payload_id. Peers echo it in their response.
    pub id: i64,
    pub parent_folder: String,
    pub attachment_hash: i64,
    pub is_sensitive: bool,
}

impl Default for FileMetadata {
    fn default() -> Self {
        Self {
            name: String::new(),
            file_type: FileType::Unknown,
            payload_id: 0,
            size: 0,
            // The schema's own default. A peer that gets an empty MIME type shows the
            // file as unknown rather than guessing from the extension.
            mime_type: "application/octet-stream".into(),
            id: 0,
            parent_folder: String::new(),
            attachment_hash: 0,
            is_sensitive: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TextMetadata {
    pub title: String,
    pub text_type: u64,
    pub payload_id: i64,
    pub size: i64,
    pub id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Introduction {
    pub files: Vec<FileMetadata>,
    pub texts: Vec<TextMetadata>,
    pub start_transfer: bool,
}

impl Introduction {
    /// Total bytes across every attachment, for a progress denominator.
    pub fn total_size(&self) -> i64 {
        self.files
            .iter()
            .map(|f| f.size)
            .chain(self.texts.iter().map(|t| t.size))
            .fold(0i64, |a, b| a.saturating_add(b))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Introduction(Introduction),
    Response(Status),
    PairedKeyEncryption {
        signed_data: Vec<u8>,
        secret_id_hash: Vec<u8>,
    },
    PairedKeyResult(PairedKeyResult),
    Cancel,
    Unknown(u64),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Protobuf(protobuf::Error),
    Malformed(&'static str),
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protobuf(e) => write!(f, "sharing: {e}"),
            Error::Malformed(w) => write!(f, "sharing: malformed ({w})"),
            Error::Crypto => write!(f, "sharing: could not get random bytes"),
        }
    }
}

impl From<protobuf::Error> for Error {
    fn from(e: protobuf::Error) -> Self {
        Error::Protobuf(e)
    }
}

// ------------------------------------------------------------------ encoding ---

fn wrap(frame_type: u64, field: u32, body: &[u8]) -> Vec<u8> {
    let mut v1 = Writer::new();
    v1.varint(V1_TYPE, frame_type);
    if !body.is_empty() || field != 0 {
        v1.bytes(field, body);
    }
    let v1 = v1.finish();

    let mut f = Writer::new();
    f.varint(F_VERSION, VERSION_V1).bytes(F_V1, &v1);
    f.finish()
}

fn encode_file(f: &FileMetadata) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(FM_NAME, f.name.as_bytes())
        .varint(FM_TYPE, f.file_type as u64)
        .varint(FM_PAYLOAD_ID, f.payload_id as u64)
        .varint(FM_SIZE, f.size as u64)
        .bytes(FM_MIME_TYPE, f.mime_type.as_bytes())
        .varint(FM_ID, f.id as u64);
    if !f.parent_folder.is_empty() {
        w.bytes(FM_PARENT_FOLDER, f.parent_folder.as_bytes());
    }
    if f.attachment_hash != 0 {
        w.varint(FM_ATTACHMENT_HASH, f.attachment_hash as u64);
    }
    if f.is_sensitive {
        w.varint(FM_IS_SENSITIVE, 1);
    }
    w.finish()
}

fn encode_text(t: &TextMetadata) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(TM_TITLE, t.title.as_bytes())
        .varint(TM_TYPE, t.text_type)
        .varint(TM_PAYLOAD_ID, t.payload_id as u64)
        .varint(TM_SIZE, t.size as u64)
        .varint(TM_ID, t.id as u64);
    w.finish()
}

/// The file list. Sent by whoever is sending, before any bytes move.
pub fn introduction(intro: &Introduction) -> Vec<u8> {
    let mut w = Writer::new();
    for f in &intro.files {
        w.bytes(IN_FILE_METADATA, &encode_file(f));
    }
    for t in &intro.texts {
        w.bytes(IN_TEXT_METADATA, &encode_text(t));
    }
    if intro.start_transfer {
        w.varint(IN_START_TRANSFER, 1);
    }
    // ALWAYS. Absent, the field reads as UNKNOWN, and a Samsung receiver treats the
    // introduction as malformed and falls through to a path that never registers the
    // attachment -- so the transfer is accepted, the bytes arrive, and no file appears.
    // Not a parameter, because there is no other use case this daemon has.
    w.varint(IN_USE_CASE, USE_CASE_NEARBY_SHARE);
    wrap(T_INTRODUCTION, V1_INTRODUCTION, &w.finish())
}

/// Accept or refuse an introduction. This is the frame a human's decision becomes.
pub fn response(status: Status) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(RS_STATUS, status as u64);
    wrap(T_RESPONSE, V1_RESPONSE, &w.finish())
}

/// The identity claim, filled with random bytes because we have no identity to claim.
///
/// Random rather than zero or empty on purpose: a peer that sees well-formed fields it
/// cannot match falls through to its everyone-visible path, whereas absent or obviously
/// empty fields have been seen to end the connection instead.
pub fn paired_key_encryption() -> Result<Vec<u8>, Error> {
    let mut signed = vec![0u8; SIGNED_DATA_LEN];
    let mut hash = vec![0u8; SECRET_ID_HASH_LEN];
    openssl::rand::rand_bytes(&mut signed).map_err(|_| Error::Crypto)?;
    openssl::rand::rand_bytes(&mut hash).map_err(|_| Error::Crypto)?;

    let mut w = Writer::new();
    w.bytes(PKE_SIGNED_DATA, &signed)
        .bytes(PKE_SECRET_ID_HASH, &hash);
    Ok(wrap(
        T_PAIRED_KEY_ENCRYPTION,
        V1_PAIRED_KEY_ENCRYPTION,
        &w.finish(),
    ))
}

/// Our verdict on the peer's identity claim. Always `Unable`: we have no certificate
/// store to check it against, and claiming Success would be a lie the peer may act on.
pub fn paired_key_result(status: PairedKeyResult) -> Vec<u8> {
    let mut w = Writer::new();
    w.varint(PKR_STATUS, status as u64);
    wrap(T_PAIRED_KEY_RESULT, V1_PAIRED_KEY_RESULT, &w.finish())
}

/// Abort a transfer in progress. Sent by either side.
pub fn cancel() -> Vec<u8> {
    let mut v1 = Writer::new();
    v1.varint(V1_TYPE, T_CANCEL);
    let v1 = v1.finish();
    let mut f = Writer::new();
    f.varint(F_VERSION, VERSION_V1).bytes(F_V1, &v1);
    f.finish()
}

// ------------------------------------------------------------------ decoding ---

pub fn parse(bytes: &[u8]) -> Result<Frame, Error> {
    let v1 = protobuf::first_bytes(bytes, F_V1)?.ok_or(Error::Malformed("no v1 frame"))?;

    let mut ty = None;
    let mut body: Option<&[u8]> = None;
    let mut r = Reader::new(v1);
    while let Some(f) = r.next_field() {
        match f? {
            Field::Varint(V1_TYPE, v) => ty = Some(v),
            Field::Bytes(_, b) => body = Some(b),
            _ => {}
        }
    }
    let ty = ty.ok_or(Error::Malformed("no frame type"))?;
    let body = body.unwrap_or(&[]);

    Ok(match ty {
        T_INTRODUCTION => Frame::Introduction(parse_introduction(body)?),
        T_RESPONSE => Frame::Response(Status::from(
            protobuf::first_varint(body, RS_STATUS)?.unwrap_or(0),
        )),
        T_PAIRED_KEY_ENCRYPTION => Frame::PairedKeyEncryption {
            signed_data: protobuf::first_bytes(body, PKE_SIGNED_DATA)?
                .unwrap_or(&[])
                .to_vec(),
            secret_id_hash: protobuf::first_bytes(body, PKE_SECRET_ID_HASH)?
                .unwrap_or(&[])
                .to_vec(),
        },
        T_PAIRED_KEY_RESULT => Frame::PairedKeyResult(PairedKeyResult::from(
            protobuf::first_varint(body, PKR_STATUS)?.unwrap_or(0),
        )),
        T_CANCEL => Frame::Cancel,
        other => Frame::Unknown(other),
    })
}

fn parse_introduction(b: &[u8]) -> Result<Introduction, Error> {
    let mut out = Introduction::default();
    let mut r = Reader::new(b);
    while let Some(f) = r.next_field() {
        match f? {
            // REPEATED, so each occurrence is a separate attachment. Taking only the
            // last would turn a five-file share into a one-file share, and the four
            // missing payloads would then arrive with no metadata to place them.
            Field::Bytes(IN_FILE_METADATA, v) => out.files.push(parse_file(v)?),
            Field::Bytes(IN_TEXT_METADATA, v) => out.texts.push(parse_text(v)?),
            Field::Varint(IN_START_TRANSFER, v) => out.start_transfer = v != 0,
            _ => {}
        }
    }
    Ok(out)
}

fn parse_file(b: &[u8]) -> Result<FileMetadata, Error> {
    Ok(FileMetadata {
        name: protobuf::first_bytes(b, FM_NAME)?.map(string).unwrap_or_default(),
        file_type: FileType::from(protobuf::first_varint(b, FM_TYPE)?.unwrap_or(0)),
        payload_id: protobuf::first_varint(b, FM_PAYLOAD_ID)?.unwrap_or(0) as i64,
        size: protobuf::first_varint(b, FM_SIZE)?.unwrap_or(0) as i64,
        mime_type: protobuf::first_bytes(b, FM_MIME_TYPE)?
            .map(string)
            .unwrap_or_else(|| "application/octet-stream".into()),
        id: protobuf::first_varint(b, FM_ID)?.unwrap_or(0) as i64,
        parent_folder: protobuf::first_bytes(b, FM_PARENT_FOLDER)?
            .map(string)
            .unwrap_or_default(),
        attachment_hash: protobuf::first_varint(b, FM_ATTACHMENT_HASH)?.unwrap_or(0) as i64,
        is_sensitive: protobuf::first_varint(b, FM_IS_SENSITIVE)?.unwrap_or(0) != 0,
    })
}

fn parse_text(b: &[u8]) -> Result<TextMetadata, Error> {
    Ok(TextMetadata {
        title: protobuf::first_bytes(b, TM_TITLE)?.map(string).unwrap_or_default(),
        text_type: protobuf::first_varint(b, TM_TYPE)?.unwrap_or(0),
        payload_id: protobuf::first_varint(b, TM_PAYLOAD_ID)?.unwrap_or(0) as i64,
        size: protobuf::first_varint(b, TM_SIZE)?.unwrap_or(0) as i64,
        id: protobuf::first_varint(b, TM_ID)?.unwrap_or(0) as i64,
    })
}

/// Lossy: a peer's file name is attacker-controlled and need not be UTF-8. Dropping a
/// whole transfer over one bad byte in a display string would be the wrong trade; what
/// this must never do is panic.
fn string(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_file(name: &str, payload_id: i64, size: i64) -> FileMetadata {
        FileMetadata {
            name: name.into(),
            file_type: FileType::Image,
            payload_id,
            size,
            mime_type: "image/jpeg".into(),
            id: payload_id ^ 0x5555,
            ..Default::default()
        }
    }

    #[test]
    fn introduction_round_trips() {
        let intro = Introduction {
            files: vec![a_file("a.jpg", -12345, 1000), a_file("b.jpg", 999, 2000)],
            texts: vec![],
            start_transfer: true,
        };
        match parse(&introduction(&intro)).unwrap() {
            Frame::Introduction(got) => assert_eq!(got, intro),
            other => panic!("wrong frame: {other:?}"),
        }
    }

    /// The failure this guards is specific: keeping only the last repeated field turns a
    /// multi-file share into a single-file one, and the other payloads then arrive with
    /// no metadata to place them.
    #[test]
    fn every_file_in_a_multi_file_introduction_survives() {
        let files: Vec<FileMetadata> = (0..12)
            .map(|i| a_file(&format!("file{i}.jpg"), i as i64 * 1000 - 5000, i as i64 * 7))
            .collect();
        let intro = Introduction {
            files: files.clone(),
            ..Default::default()
        };
        match parse(&introduction(&intro)).unwrap() {
            Frame::Introduction(got) => {
                assert_eq!(got.files.len(), 12);
                assert_eq!(got.files, files);
            }
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[test]
    fn response_round_trips_every_status() {
        for s in [
            Status::Accept,
            Status::Reject,
            Status::NotEnoughSpace,
            Status::UnsupportedAttachmentType,
            Status::TimedOut,
        ] {
            assert_eq!(parse(&response(s)).unwrap(), Frame::Response(s));
        }
    }

    #[test]
    fn paired_key_encryption_has_the_field_test_lengths() {
        match parse(&paired_key_encryption().unwrap()).unwrap() {
            Frame::PairedKeyEncryption {
                signed_data,
                secret_id_hash,
            } => {
                assert_eq!(signed_data.len(), SIGNED_DATA_LEN);
                assert_eq!(secret_id_hash.len(), SECRET_ID_HASH_LEN);
            }
            other => panic!("wrong frame: {other:?}"),
        }
    }

    /// Two frames must not share fill bytes. They are meaningless, but a fixed value
    /// would be a stable fingerprint of this implementation across every connection.
    #[test]
    fn paired_key_fill_is_fresh_each_time() {
        let a = paired_key_encryption().unwrap();
        let b = paired_key_encryption().unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn paired_key_result_round_trips() {
        assert_eq!(
            parse(&paired_key_result(PairedKeyResult::Unable)).unwrap(),
            Frame::PairedKeyResult(PairedKeyResult::Unable)
        );
    }

    #[test]
    fn cancel_round_trips() {
        assert_eq!(parse(&cancel()).unwrap(), Frame::Cancel);
    }

    #[test]
    fn an_unmodelled_type_is_reported_not_refused() {
        let body = wrap(7, 7, b"progress"); // PROGRESS_UPDATE, deprecated
        assert_eq!(parse(&body).unwrap(), Frame::Unknown(7));
    }

    /// A missing mime_type must come back as the schema default, not as empty. A peer
    /// that omits it is relying on that default to pick an icon.
    #[test]
    fn a_missing_mime_type_becomes_the_schema_default() {
        let mut w = Writer::new();
        w.bytes(FM_NAME, b"x.bin").varint(FM_PAYLOAD_ID, 5);
        let mut i = Writer::new();
        i.bytes(IN_FILE_METADATA, &w.finish());
        let body = wrap(T_INTRODUCTION, V1_INTRODUCTION, &i.finish());
        match parse(&body).unwrap() {
            Frame::Introduction(got) => {
                assert_eq!(got.files[0].mime_type, "application/octet-stream")
            }
            other => panic!("wrong frame: {other:?}"),
        }
    }

    #[test]
    fn total_size_sums_and_does_not_overflow() {
        let intro = Introduction {
            files: vec![
                FileMetadata { size: i64::MAX, ..Default::default() },
                FileMetadata { size: i64::MAX, ..Default::default() },
            ],
            ..Default::default()
        };
        assert_eq!(intro.total_size(), i64::MAX);
    }

    #[test]
    fn mime_types_map_to_plausible_kinds() {
        assert_eq!(FileType::of_mime("image/png"), FileType::Image);
        assert_eq!(FileType::of_mime("video/mp4"), FileType::Video);
        assert_eq!(FileType::of_mime("audio/mpeg"), FileType::Audio);
        assert_eq!(FileType::of_mime("application/pdf"), FileType::Document);
        assert_eq!(
            FileType::of_mime("application/vnd.android.package-archive"),
            FileType::AndroidApp
        );
        assert_eq!(FileType::of_mime("application/zip"), FileType::Unknown);
        assert_eq!(FileType::of_mime(""), FileType::Unknown);
    }

    #[test]
    fn a_non_utf8_name_does_not_panic() {
        let mut w = Writer::new();
        w.bytes(FM_NAME, &[0xFF, 0xFE, 0xFD]).varint(FM_PAYLOAD_ID, 1);
        let mut i = Writer::new();
        i.bytes(IN_FILE_METADATA, &w.finish());
        let body = wrap(T_INTRODUCTION, V1_INTRODUCTION, &i.finish());
        assert!(parse(&body).is_ok());
    }

    #[test]
    fn truncation_and_garbage_do_not_panic() {
        let intro = Introduction {
            files: vec![a_file("x.jpg", 7, 7)],
            ..Default::default()
        };
        let full = introduction(&intro);
        for cut in 0..full.len() {
            let _ = parse(&full[..cut]);
        }
        for len in 0..64 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 53 + 7) as u8).collect();
            let _ = parse(&junk);
        }
    }
}
