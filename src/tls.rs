use std::collections::BTreeMap;
use std::ffi::{CStr, c_void};
use std::slice;

use anyhow::{Context, Result, bail};
use boring::ssl::SslRef;
use foreign_types_shared::ForeignTypeRef;
use serde::{Deserialize, Serialize};

use crate::model::{ProviderEvidenceChannel, ProviderSignal};

pub const TLS_MORPHOLOGY_VERSION: &str = "builtin-tls-morphology-v1";

const TLS_HANDSHAKE: i32 = 22;
const TLS_CHANGE_CIPHER_SPEC: i32 = 20;
const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_COMPRESSED_CERTIFICATE: u8 = 25;

const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsExtensionShape {
    pub id: u16,
    pub length: u16,
    pub grease: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsHandshakeMessageShape {
    pub message_type: u8,
    pub name: String,
    pub body_length: u32,
    pub wire_length: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsSessionTicketShape {
    pub length: u32,
    pub lifetime_hint: u32,
    pub lifetime_bucket_60s: u32,
    pub nonce_length: u8,
    pub extension_ids: Vec<u16>,
    pub grease_extension_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsServerMorphology {
    pub classifier: String,
    pub client_profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_cipher_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_group_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    pub hello_retry_request: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hrr_requested_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hrr_requested_group_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serverhello_length: Option<u32>,
    #[serde(default)]
    pub serverhello_extension_ids: Vec<u16>,
    pub serverhello_grease_extension_count: usize,
    pub compat_ccs_before_encrypted_extensions: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_extensions_length: Option<u32>,
    #[serde(default)]
    pub encrypted_extension_ids: Vec<u16>,
    pub encrypted_grease_extension_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_list_length: Option<u32>,
    #[serde(default)]
    pub certificate_lengths: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compressed_certificate_length: Option<u32>,
    pub new_session_ticket_count: usize,
    #[serde(default)]
    pub new_session_tickets: Vec<TlsSessionTicketShape>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_handshake_window_ms: Option<u128>,
    #[serde(default)]
    pub handshake_messages: Vec<TlsHandshakeMessageShape>,
    #[serde(default)]
    pub handshake_lengths: BTreeMap<String, Vec<u32>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_match: Option<TlsMorphologyMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsMorphologyMatch {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_family: Option<String>,
    pub implementation_family: String,
}

#[derive(Debug, Clone)]
enum CapturedTlsEvent {
    Handshake(Vec<u8>),
    ChangeCipherSpec,
}

#[derive(Debug, Default)]
struct CaptureState {
    events: Vec<CapturedTlsEvent>,
}

pub struct TlsMessageCapture {
    state: Box<CaptureState>,
}

impl Default for TlsMessageCapture {
    fn default() -> Self {
        Self {
            state: Box::new(CaptureState::default()),
        }
    }
}

impl TlsMessageCapture {
    /// Install a per-connection BoringSSL message callback.
    ///
    /// BoringSSL invokes this synchronously with complete, already-decrypted
    /// handshake messages and compatibility CCS bodies. The capture object must
    /// outlive the SSL object on which it is installed.
    pub fn install(&mut self, ssl: &mut SslRef) {
        let arg = (&mut *self.state) as *mut CaptureState as *mut c_void;
        unsafe {
            boring_sys::SSL_set_msg_callback(ssl.as_ptr(), Some(raw_message_callback));
            boring_sys::SSL_set_msg_callback_arg(ssl.as_ptr(), arg);
        }
    }

    pub fn morphology(
        &self,
        client_profile: impl Into<String>,
        selected_alpn: Option<&[u8]>,
    ) -> Result<TlsServerMorphology> {
        parse_capture(&self.state.events, client_profile.into(), selected_alpn)
    }
}

unsafe extern "C" fn raw_message_callback(
    is_write: i32,
    _version: i32,
    content_type: i32,
    buf: *const c_void,
    len: usize,
    _ssl: *mut boring_sys::SSL,
    arg: *mut c_void,
) {
    if is_write != 0 || arg.is_null() {
        return;
    }
    let state = unsafe { &mut *(arg as *mut CaptureState) };
    match content_type {
        TLS_HANDSHAKE if !buf.is_null() && len >= 4 => {
            let bytes = unsafe { slice::from_raw_parts(buf.cast::<u8>(), len) };
            state
                .events
                .push(CapturedTlsEvent::Handshake(bytes.to_vec()));
        }
        TLS_CHANGE_CIPHER_SPEC => state.events.push(CapturedTlsEvent::ChangeCipherSpec),
        _ => {}
    }
}

#[derive(Debug)]
struct ParsedServerHello {
    length: u32,
    cipher_suite: u16,
    group_id: Option<u16>,
    is_hrr: bool,
    extensions: Vec<TlsExtensionShape>,
}

#[derive(Debug)]
struct ParsedEncryptedExtensions {
    length: u32,
    extensions: Vec<TlsExtensionShape>,
    alpn: Option<String>,
}

fn parse_capture(
    events: &[CapturedTlsEvent],
    client_profile: String,
    selected_alpn: Option<&[u8]>,
) -> Result<TlsServerMorphology> {
    let mut server_hellos = Vec::new();
    let mut encrypted_extensions = None;
    let mut tickets = Vec::new();
    let mut compressed_certificate_length = None;
    let mut certificate_list_length = None;
    let mut certificate_lengths = Vec::new();
    let mut handshake_messages = Vec::new();
    let mut handshake_lengths = BTreeMap::<String, Vec<u32>>::new();
    let mut seen_server_hello = false;
    let mut seen_encrypted_extensions = false;
    let mut compatibility_ccs = false;

    for event in events {
        match event {
            CapturedTlsEvent::ChangeCipherSpec => {
                if seen_server_hello && !seen_encrypted_extensions {
                    compatibility_ccs = true;
                }
            }
            CapturedTlsEvent::Handshake(message) => {
                let (message_type, body_length, body) = handshake_body(message)?;
                let name = handshake_name(message_type).to_owned();
                handshake_lengths
                    .entry(name.clone())
                    .or_default()
                    .push(body_length);
                handshake_messages.push(TlsHandshakeMessageShape {
                    message_type,
                    name,
                    body_length,
                    wire_length: body_length.saturating_add(4),
                });
                match message_type {
                    HS_SERVER_HELLO => {
                        seen_server_hello = true;
                        server_hellos.push(parse_server_hello(body_length, body)?);
                    }
                    HS_ENCRYPTED_EXTENSIONS => {
                        seen_encrypted_extensions = true;
                        encrypted_extensions = Some(parse_encrypted_extensions(body_length, body)?);
                    }
                    HS_CERTIFICATE => {
                        if let Ok((list_length, lengths)) = parse_certificate(body) {
                            certificate_list_length = Some(list_length);
                            certificate_lengths = lengths;
                        }
                    }
                    HS_COMPRESSED_CERTIFICATE => {
                        compressed_certificate_length = Some(body_length);
                    }
                    HS_NEW_SESSION_TICKET => {
                        tickets.push(parse_new_session_ticket(body_length, body)?)
                    }
                    HS_CERTIFICATE_VERIFY | HS_FINISHED => {}
                    _ => {}
                }
            }
        }
    }

    let final_server_hello = server_hellos
        .iter()
        .rev()
        .find(|server_hello| !server_hello.is_hrr)
        .or_else(|| server_hellos.last())
        .context("no received ServerHello captured")?;
    let hrr = server_hellos
        .iter()
        .find(|server_hello| server_hello.is_hrr);
    let ee = encrypted_extensions.context("no received EncryptedExtensions captured")?;
    let selected_group_id = final_server_hello.group_id;
    let hrr_group_id = hrr.and_then(|server_hello| server_hello.group_id);
    let alpn = ee
        .alpn
        .or_else(|| selected_alpn.map(|value| String::from_utf8_lossy(value).into_owned()));

    let mut morphology = TlsServerMorphology {
        classifier: TLS_MORPHOLOGY_VERSION.into(),
        client_profile,
        selected_cipher: Some(cipher_name(final_server_hello.cipher_suite).to_owned()),
        selected_cipher_id: Some(final_server_hello.cipher_suite),
        selected_group: selected_group_id.map(group_name),
        selected_group_id,
        alpn,
        hello_retry_request: hrr.is_some(),
        hrr_requested_group: hrr_group_id.map(group_name),
        hrr_requested_group_id: hrr_group_id,
        serverhello_length: Some(final_server_hello.length),
        serverhello_extension_ids: non_grease_ids(&final_server_hello.extensions),
        serverhello_grease_extension_count: grease_count(&final_server_hello.extensions),
        compat_ccs_before_encrypted_extensions: compatibility_ccs,
        encrypted_extensions_length: Some(ee.length),
        encrypted_extension_ids: non_grease_ids(&ee.extensions),
        encrypted_grease_extension_count: grease_count(&ee.extensions),
        certificate_list_length,
        certificate_lengths,
        compressed_certificate_length,
        new_session_ticket_count: tickets.len(),
        new_session_tickets: tickets,
        post_handshake_window_ms: None,
        handshake_messages,
        handshake_lengths,
        family_match: None,
    };
    morphology.family_match = classify_morphology(&morphology);
    Ok(morphology)
}

fn handshake_body(message: &[u8]) -> Result<(u8, u32, &[u8])> {
    if message.len() < 4 {
        bail!("TLS handshake message is shorter than its header");
    }
    let body_length = u32::from_be_bytes([0, message[1], message[2], message[3]]);
    let expected = usize::try_from(body_length)
        .context("TLS handshake body length overflow")?
        .checked_add(4)
        .context("TLS handshake wire length overflow")?;
    if message.len() != expected {
        bail!(
            "TLS handshake length mismatch: header says {body_length}, callback supplied {} bytes",
            message.len()
        );
    }
    Ok((message[0], body_length, &message[4..]))
}

fn parse_server_hello(length: u32, body: &[u8]) -> Result<ParsedServerHello> {
    let mut cursor = Cursor::new(body);
    cursor.take(2, "ServerHello legacy_version")?;
    let random = cursor.take(32, "ServerHello random")?;
    let is_hrr = random == HRR_RANDOM;
    let session_id_len = usize::from(cursor.u8("ServerHello session id length")?);
    cursor.take(session_id_len, "ServerHello session id")?;
    let cipher_suite = cursor.u16("ServerHello cipher suite")?;
    cursor.take(1, "ServerHello compression")?;
    let (extensions, values) =
        parse_extension_vector_with_values(&mut cursor, "ServerHello extensions")?;
    cursor.finish("ServerHello")?;
    let group_id = extensions
        .iter()
        .position(|extension| extension.id == 51)
        .and_then(|index| values[index].get(..2))
        .map(|value| u16::from_be_bytes([value[0], value[1]]));

    Ok(ParsedServerHello {
        length,
        cipher_suite,
        group_id,
        is_hrr,
        extensions,
    })
}

fn parse_encrypted_extensions(length: u32, body: &[u8]) -> Result<ParsedEncryptedExtensions> {
    let mut cursor = Cursor::new(body);
    let (extensions, values) =
        parse_extension_vector_with_values(&mut cursor, "EncryptedExtensions")?;
    cursor.finish("EncryptedExtensions")?;
    let alpn = extensions
        .iter()
        .position(|extension| extension.id == 16)
        .and_then(|index| parse_alpn(values[index]).ok().flatten());
    Ok(ParsedEncryptedExtensions {
        length,
        extensions,
        alpn,
    })
}

fn parse_new_session_ticket(length: u32, body: &[u8]) -> Result<TlsSessionTicketShape> {
    let mut cursor = Cursor::new(body);
    let lifetime_hint = cursor.u32("NewSessionTicket lifetime")?;
    cursor.take(4, "NewSessionTicket age_add")?;
    let nonce_length = cursor.u8("NewSessionTicket nonce length")?;
    cursor.take(usize::from(nonce_length), "NewSessionTicket nonce")?;
    let ticket_length = usize::from(cursor.u16("NewSessionTicket ticket length")?);
    cursor.take(ticket_length, "NewSessionTicket ticket")?;
    let extensions = parse_extension_vector(&mut cursor, "NewSessionTicket extensions")?;
    cursor.finish("NewSessionTicket")?;
    Ok(TlsSessionTicketShape {
        length,
        lifetime_hint,
        lifetime_bucket_60s: lifetime_hint.saturating_add(30) / 60 * 60,
        nonce_length,
        extension_ids: non_grease_ids(&extensions),
        grease_extension_count: grease_count(&extensions),
    })
}

fn parse_certificate(body: &[u8]) -> Result<(u32, Vec<u32>)> {
    let mut cursor = Cursor::new(body);
    let context_len = usize::from(cursor.u8("Certificate request context length")?);
    cursor.take(context_len, "Certificate request context")?;
    let list_len = cursor.u24("Certificate list length")?;
    let list = cursor.take(
        usize::try_from(list_len).context("Certificate list length overflow")?,
        "Certificate list",
    )?;
    cursor.finish("Certificate")?;
    let mut list_cursor = Cursor::new(list);
    let mut lengths = Vec::new();
    while list_cursor.remaining() > 0 {
        let cert_len = list_cursor.u24("Certificate ASN.1 length")?;
        list_cursor.take(
            usize::try_from(cert_len).context("Certificate length overflow")?,
            "Certificate ASN.1 body",
        )?;
        let ext_len = usize::from(list_cursor.u16("Certificate entry extension length")?);
        list_cursor.take(ext_len, "Certificate entry extensions")?;
        lengths.push(cert_len);
    }
    Ok((list_len, lengths))
}

fn parse_extension_vector(
    cursor: &mut Cursor<'_>,
    context: &str,
) -> Result<Vec<TlsExtensionShape>> {
    let (extensions, _) = parse_extension_vector_with_values(cursor, context)?;
    Ok(extensions)
}

fn parse_extension_vector_with_values<'a>(
    cursor: &mut Cursor<'a>,
    context: &str,
) -> Result<(Vec<TlsExtensionShape>, Vec<&'a [u8]>)> {
    let total = usize::from(cursor.u16(&format!("{context} length"))?);
    let payload = cursor.take(total, context)?;
    let mut ext_cursor = Cursor::new(payload);
    let mut extensions = Vec::new();
    let mut values = Vec::new();
    while ext_cursor.remaining() > 0 {
        let id = ext_cursor.u16(&format!("{context} extension id"))?;
        let length = ext_cursor.u16(&format!("{context} extension length"))?;
        let value = ext_cursor.take(usize::from(length), context)?;
        extensions.push(TlsExtensionShape {
            id,
            length,
            grease: is_grease_u16(id),
        });
        values.push(value);
    }
    Ok((extensions, values))
}

fn parse_alpn(value: &[u8]) -> Result<Option<String>> {
    let mut cursor = Cursor::new(value);
    let total = usize::from(cursor.u16("ALPN protocol list length")?);
    let list = cursor.take(total, "ALPN protocol list")?;
    cursor.finish("ALPN extension")?;
    if list.is_empty() {
        return Ok(None);
    }
    let name_len = usize::from(list[0]);
    if list.len() < name_len + 1 {
        bail!("ALPN selected protocol is truncated");
    }
    Ok(Some(
        String::from_utf8_lossy(&list[1..1 + name_len]).into_owned(),
    ))
}

fn classify_morphology(morphology: &TlsServerMorphology) -> Option<TlsMorphologyMatch> {
    // Provider rules are intentionally profile-specific and confirmatory-only.
    // They were calibrated on repeated 2026-10-24 observations from unrelated
    // routes using the exact deterministic default BoringSSL observer profile.
    // A custom group list (or any future profile) must be calibrated separately.
    if morphology.client_profile == "boringssl-h2-tls13-v1" {
        if matches_cloudflare_default_profile(morphology) {
            return Some(provider_match(
                "cloudflare-boringssl-h2-tls13-v1",
                "cloudflare",
                "openssl-boringssl-family-shape",
            ));
        }
        if matches_akamai_default_profile(morphology) {
            return Some(provider_match(
                "akamai-boringssl-h2-tls13-v1",
                "akamai",
                "openssl-boringssl-family-shape",
            ));
        }
        if matches_imperva_default_profile(morphology) {
            return Some(provider_match(
                "imperva-boringssl-h2-tls13-v1",
                "imperva",
                "openssl-boringssl-family-shape",
            ));
        }
        if matches_fastly_default_profile(morphology) {
            return Some(provider_match(
                "fastly-boringssl-h2-tls13-v1",
                "fastly",
                "openssl-boringssl-family-shape",
            ));
        }
    }

    // Broader implementation/configuration shapes are useful descriptive
    // evidence but never emit provider identity.
    let implementation_family = if morphology.encrypted_extension_ids == [16, 0] {
        Some("go-crypto-tls-like")
    } else if morphology.serverhello_extension_ids == [51, 43]
        && morphology.encrypted_extension_ids == [16]
    {
        Some("google-or-f5-like")
    } else if matches!(
        (
            morphology.serverhello_extension_ids.as_slice(),
            morphology.encrypted_extension_ids.as_slice()
        ),
        ([43, 51], [0, 16]) | ([51, 43], [0, 16])
    ) {
        Some("openssl-boringssl-family-shape")
    } else {
        None
    }?;
    Some(TlsMorphologyMatch {
        name: format!("{implementation_family}-v1"),
        provider_family: None,
        implementation_family: implementation_family.into(),
    })
}

fn provider_match(name: &str, provider: &str, implementation_family: &str) -> TlsMorphologyMatch {
    TlsMorphologyMatch {
        name: name.into(),
        provider_family: Some(provider.into()),
        implementation_family: implementation_family.into(),
    }
}

fn matches_common_default_profile(
    morphology: &TlsServerMorphology,
    cipher_id: u16,
    serverhello_extension_ids: &[u16],
    encrypted_extension_ids: &[u16],
) -> bool {
    morphology.selected_cipher_id == Some(cipher_id)
        && morphology.selected_group_id == Some(0x11ec)
        && morphology.alpn.as_deref() == Some("h2")
        && !morphology.hello_retry_request
        && morphology.serverhello_length == Some(1206)
        && morphology.serverhello_extension_ids == serverhello_extension_ids
        && morphology.encrypted_extensions_length
            == Some(if encrypted_extension_ids == [16] {
                11
            } else {
                15
            })
        && morphology.encrypted_extension_ids == encrypted_extension_ids
        && morphology.compressed_certificate_length.is_none()
}

fn tickets_match(
    morphology: &TlsServerMorphology,
    count: usize,
    mut predicate: impl FnMut(&TlsSessionTicketShape) -> bool,
) -> bool {
    morphology.new_session_ticket_count == count
        && morphology.new_session_tickets.len() == count
        && morphology.new_session_tickets.iter().all(&mut predicate)
}

fn matches_cloudflare_default_profile(morphology: &TlsServerMorphology) -> bool {
    matches_common_default_profile(morphology, 0x1301, &[51, 43], &[0, 16])
        && tickets_match(morphology, 2, |ticket| {
            ticket.length == 210
                && ticket.lifetime_bucket_60s == 64_800
                && ticket.nonce_length == 1
                && ticket.extension_ids.is_empty()
                && ticket.grease_extension_count == 1
        })
}

fn matches_akamai_default_profile(morphology: &TlsServerMorphology) -> bool {
    matches_common_default_profile(morphology, 0x1302, &[43, 51], &[0, 16])
        && tickets_match(morphology, 2, |ticket| {
            ticket.length == 277
                && ticket.lifetime_bucket_60s == 83_100
                && ticket.nonce_length == 8
                && ticket.extension_ids.is_empty()
                && ticket.grease_extension_count == 0
        })
}

fn matches_imperva_default_profile(morphology: &TlsServerMorphology) -> bool {
    matches_common_default_profile(morphology, 0x1301, &[43, 51], &[0, 16])
        && tickets_match(morphology, 2, |ticket| {
            ticket.length == 245
                && ticket.lifetime_bucket_60s == 7_200
                && ticket.nonce_length == 8
                && ticket.extension_ids.is_empty()
                && ticket.grease_extension_count == 0
        })
}

fn matches_fastly_default_profile(morphology: &TlsServerMorphology) -> bool {
    matches_common_default_profile(morphology, 0x1301, &[43, 51], &[0, 16])
        && tickets_match(morphology, 1, |ticket| {
            ticket.lifetime_bucket_60s == 86_400
                && ticket.nonce_length == 0
                && ticket.grease_extension_count == 0
                && matches!(
                    (ticket.length, ticket.extension_ids.as_slice()),
                    (189, []) | (197, [42])
                )
        })
}

pub fn provider_signals(morphology: &TlsServerMorphology) -> Vec<ProviderSignal> {
    let Some(matched) = &morphology.family_match else {
        return Vec::new();
    };
    let Some(provider) = &matched.provider_family else {
        return Vec::new();
    };
    vec![ProviderSignal {
        provider: provider.clone(),
        channel: ProviderEvidenceChannel::TlsMorphology,
        classifier: TLS_MORPHOLOGY_VERSION.into(),
        evidence: vec![format!("tls-morphology:{}", matched.name)],
    }]
}

fn non_grease_ids(extensions: &[TlsExtensionShape]) -> Vec<u16> {
    extensions
        .iter()
        .filter(|extension| !extension.grease)
        .map(|extension| extension.id)
        .collect()
}

fn grease_count(extensions: &[TlsExtensionShape]) -> usize {
    extensions
        .iter()
        .filter(|extension| extension.grease)
        .count()
}

pub fn is_grease_u16(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) as u8 == value as u8
}

fn cipher_name(id: u16) -> &'static str {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => "unknown",
    }
}

fn group_name(id: u16) -> String {
    unsafe {
        let ptr = boring_sys::SSL_get_group_name(id);
        if !ptr.is_null() {
            return CStr::from_ptr(ptr).to_string_lossy().into_owned();
        }
    }
    format!("unknown({id})")
}

fn handshake_name(message_type: u8) -> &'static str {
    match message_type {
        HS_SERVER_HELLO => "ServerHello",
        HS_NEW_SESSION_TICKET => "NewSessionTicket",
        HS_ENCRYPTED_EXTENSIONS => "EncryptedExtensions",
        HS_CERTIFICATE => "Certificate",
        HS_CERTIFICATE_VERIFY => "CertificateVerify",
        HS_FINISHED => "Finished",
        HS_COMPRESSED_CERTIFICATE => "CompressedCertificate",
        _ => "Other",
    }
}

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn take(&mut self, length: usize, context: &str) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .with_context(|| format!("{context} length overflow"))?;
        if end > self.data.len() {
            bail!("{context} is truncated");
        }
        let out = &self.data[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn u8(&mut self, context: &str) -> Result<u8> {
        Ok(self.take(1, context)?[0])
    }

    fn u16(&mut self, context: &str) -> Result<u16> {
        let bytes = self.take(2, context)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self, context: &str) -> Result<u32> {
        let bytes = self.take(3, context)?;
        Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
    }

    fn u32(&mut self, context: &str) -> Result<u32> {
        let bytes = self.take(4, context)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn finish(&self, context: &str) -> Result<()> {
        if self.remaining() != 0 {
            bail!("{context} has {} trailing bytes", self.remaining());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hs(message_type: u8, body: &[u8]) -> Vec<u8> {
        let length = body.len() as u32;
        let mut out = vec![
            message_type,
            ((length >> 16) & 0xff) as u8,
            ((length >> 8) & 0xff) as u8,
            (length & 0xff) as u8,
        ];
        out.extend_from_slice(body);
        out
    }

    fn extension(id: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    fn extension_vector(entries: &[Vec<u8>]) -> Vec<u8> {
        let body = entries.concat();
        let mut out = Vec::new();
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend(body);
        out
    }

    fn server_hello(random: [u8; 32], group: u16, exts: &[u16]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&random);
        body.push(0);
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        body.push(0);
        let entries = exts
            .iter()
            .map(|id| match *id {
                43 => extension(43, &[0x03, 0x04]),
                51 => extension(51, &group.to_be_bytes()),
                other => extension(other, &[]),
            })
            .collect::<Vec<_>>();
        body.extend(extension_vector(&entries));
        hs(HS_SERVER_HELLO, &body)
    }

    fn ticket(
        length: u32,
        lifetime: u32,
        nonce_length: u8,
        extension_ids: Vec<u16>,
        grease_extension_count: usize,
    ) -> TlsSessionTicketShape {
        TlsSessionTicketShape {
            length,
            lifetime_hint: lifetime,
            lifetime_bucket_60s: lifetime,
            nonce_length,
            extension_ids,
            grease_extension_count,
        }
    }

    fn synthetic_morphology(
        cipher_id: u16,
        serverhello_extension_ids: Vec<u16>,
        tickets: Vec<TlsSessionTicketShape>,
    ) -> TlsServerMorphology {
        TlsServerMorphology {
            classifier: TLS_MORPHOLOGY_VERSION.into(),
            client_profile: "boringssl-h2-tls13-v1".into(),
            selected_cipher: Some(cipher_name(cipher_id).into()),
            selected_cipher_id: Some(cipher_id),
            selected_group: Some("X25519MLKEM768".into()),
            selected_group_id: Some(0x11ec),
            alpn: Some("h2".into()),
            hello_retry_request: false,
            hrr_requested_group: None,
            hrr_requested_group_id: None,
            serverhello_length: Some(1206),
            serverhello_extension_ids,
            serverhello_grease_extension_count: 0,
            compat_ccs_before_encrypted_extensions: false,
            encrypted_extensions_length: Some(15),
            encrypted_extension_ids: vec![0, 16],
            encrypted_grease_extension_count: 0,
            certificate_list_length: None,
            certificate_lengths: Vec::new(),
            compressed_certificate_length: None,
            new_session_ticket_count: tickets.len(),
            new_session_tickets: tickets,
            post_handshake_window_ms: Some(1_500),
            handshake_messages: Vec::new(),
            handshake_lengths: BTreeMap::new(),
            family_match: None,
        }
    }

    #[test]
    fn calibrated_default_profile_provider_shapes_are_confirmatory_signals() {
        let cases = [
            (
                "cloudflare",
                synthetic_morphology(
                    0x1301,
                    vec![51, 43],
                    vec![
                        ticket(210, 64_800, 1, vec![], 1),
                        ticket(210, 64_800, 1, vec![], 1),
                    ],
                ),
            ),
            (
                "akamai",
                synthetic_morphology(
                    0x1302,
                    vec![43, 51],
                    vec![
                        ticket(277, 83_100, 8, vec![], 0),
                        ticket(277, 83_100, 8, vec![], 0),
                    ],
                ),
            ),
            (
                "imperva",
                synthetic_morphology(
                    0x1301,
                    vec![43, 51],
                    vec![
                        ticket(245, 7_200, 8, vec![], 0),
                        ticket(245, 7_200, 8, vec![], 0),
                    ],
                ),
            ),
            (
                "fastly",
                synthetic_morphology(
                    0x1301,
                    vec![43, 51],
                    vec![ticket(189, 86_400, 0, vec![], 0)],
                ),
            ),
        ];

        for (provider, mut morphology) in cases {
            morphology.family_match = classify_morphology(&morphology);
            let matched = morphology.family_match.as_ref().unwrap();
            assert_eq!(matched.provider_family.as_deref(), Some(provider));
            let signals = provider_signals(&morphology);
            assert_eq!(signals.len(), 1);
            assert_eq!(signals[0].provider, provider);
            assert_eq!(signals[0].channel, ProviderEvidenceChannel::TlsMorphology);
        }
    }

    #[test]
    fn fastly_early_data_ticket_variant_is_calibrated() {
        let morphology = synthetic_morphology(
            0x1301,
            vec![43, 51],
            vec![ticket(197, 86_400, 0, vec![42], 0)],
        );
        assert_eq!(
            classify_morphology(&morphology).and_then(|matched| matched.provider_family),
            Some("fastly".into())
        );
    }

    #[test]
    fn provider_rules_do_not_apply_to_custom_client_profile() {
        let mut morphology = synthetic_morphology(
            0x1301,
            vec![51, 43],
            vec![
                ticket(210, 64_800, 1, vec![], 1),
                ticket(210, 64_800, 1, vec![], 1),
            ],
        );
        morphology.client_profile = "boringssl-h2-tls13-v1:groups=X25519".into();
        let matched = classify_morphology(&morphology).unwrap();
        assert!(matched.provider_family.is_none());
    }

    #[test]
    fn cloudfront_like_ticket_shape_does_not_match_fastly() {
        let morphology = synthetic_morphology(
            0x1301,
            vec![43, 51],
            vec![ticket(153, 52_800, 2, vec![], 0)],
        );
        let matched = classify_morphology(&morphology).unwrap();
        assert!(matched.provider_family.is_none());
        assert_eq!(
            matched.implementation_family,
            "openssl-boringssl-family-shape"
        );
    }

    #[test]
    fn grease_rule_matches_tls_reserved_pattern() {
        assert!(is_grease_u16(0x0a0a));
        assert!(is_grease_u16(0xfafa));
        assert!(!is_grease_u16(0x1301));
        assert!(!is_grease_u16(0x1a2a));
    }

    #[test]
    fn serverhello_parser_preserves_extension_order_and_detects_hrr() {
        let hrr = server_hello(HRR_RANDOM, 0x0017, &[43, 51]);
        let (_, length, body) = handshake_body(&hrr).unwrap();
        let parsed = parse_server_hello(length, body).unwrap();
        assert!(parsed.is_hrr);
        assert_eq!(parsed.group_id, Some(0x0017));
        assert_eq!(non_grease_ids(&parsed.extensions), vec![43, 51]);
    }

    #[test]
    fn encrypted_extensions_preserve_order_and_alpn() {
        let alpn = extension(16, &[0, 3, 2, b'h', b'2']);
        let server_name = extension(0, &[]);
        let body = extension_vector(&[alpn, server_name]);
        let parsed = parse_encrypted_extensions(body.len() as u32, &body).unwrap();
        assert_eq!(non_grease_ids(&parsed.extensions), vec![16, 0]);
        assert_eq!(parsed.alpn.as_deref(), Some("h2"));
    }

    #[test]
    fn new_session_ticket_excludes_random_ticket_bytes_but_keeps_shape() {
        let grease = extension(0x2a2a, &[1, 2, 3]);
        let early_data = extension(42, &[0, 0, 0, 0]);
        let mut body = Vec::new();
        body.extend_from_slice(&64801u32.to_be_bytes());
        body.extend_from_slice(&123u32.to_be_bytes());
        body.push(1);
        body.push(7);
        body.extend_from_slice(&3u16.to_be_bytes());
        body.extend_from_slice(&[9, 8, 7]);
        body.extend(extension_vector(&[grease, early_data]));
        let shape = parse_new_session_ticket(body.len() as u32, &body).unwrap();
        assert_eq!(shape.length, body.len() as u32);
        assert_eq!(shape.lifetime_hint, 64801);
        assert_eq!(shape.lifetime_bucket_60s, 64800);
        assert_eq!(shape.nonce_length, 1);
        assert_eq!(shape.extension_ids, vec![42]);
        assert_eq!(shape.grease_extension_count, 1);
    }

    #[test]
    fn complete_capture_tracks_ccs_hrr_final_hello_and_ticket() {
        let hrr = server_hello(HRR_RANDOM, 0x0017, &[43, 51]);
        let final_sh = server_hello([1; 32], 0x0017, &[43, 51]);
        let ee_body = extension_vector(&[extension(0, &[]), extension(16, &[0, 3, 2, b'h', b'2'])]);
        let mut ticket_body = Vec::new();
        ticket_body.extend_from_slice(&7200u32.to_be_bytes());
        ticket_body.extend_from_slice(&1u32.to_be_bytes());
        ticket_body.push(8);
        ticket_body.extend_from_slice(&[0; 8]);
        ticket_body.extend_from_slice(&1u16.to_be_bytes());
        ticket_body.push(9);
        ticket_body.extend_from_slice(&0u16.to_be_bytes());
        let events = vec![
            CapturedTlsEvent::Handshake(hrr),
            CapturedTlsEvent::ChangeCipherSpec,
            CapturedTlsEvent::Handshake(final_sh),
            CapturedTlsEvent::Handshake(hs(HS_ENCRYPTED_EXTENSIONS, &ee_body)),
            CapturedTlsEvent::Handshake(hs(HS_NEW_SESSION_TICKET, &ticket_body)),
        ];
        let morphology = parse_capture(&events, "test-profile".into(), Some(b"h2")).unwrap();
        assert!(morphology.hello_retry_request);
        assert_eq!(morphology.hrr_requested_group_id, Some(0x0017));
        assert_eq!(morphology.selected_group_id, Some(0x0017));
        assert_eq!(morphology.serverhello_extension_ids, vec![43, 51]);
        assert_eq!(morphology.encrypted_extension_ids, vec![0, 16]);
        assert!(morphology.compat_ccs_before_encrypted_extensions);
        assert_eq!(morphology.new_session_ticket_count, 1);
    }
}
