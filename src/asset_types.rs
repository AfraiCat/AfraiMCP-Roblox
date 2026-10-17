//! Asset types, file extensions, content types and validation for Open Cloud
//! uploads (plan step 2, `Claude-Migration/plans/roblox-mcp-direct-upload.md`).
//!
//! The Assets API defines seven `assetType` values: Animation, Audio, Decal,
//! Image, Mesh, Model and Video ([`AssetKind`]). Each kind accepts a fixed set
//! of file formats ([`FileFormat`]); the `fileContent` multipart part must be
//! sent with an explicit content type, which the old `mime_guess` lookup could
//! not provide for FBX or GLB.
//!
//! Validation never trusts the file name alone: [`validate_upload`] checks the
//! size, that the extension belongs to the requested kind, and that the first
//! bytes of the file match the format the extension claims (PNG signature, GLB
//! header, `Kaydara FBX Binary`, and so on). A `.png` that is really a JPEG, or
//! an `.fbx` that is really text, is rejected before any network call.
//!
//! Content types: the table in [`FORMAT_TABLE`] is the **only** place they are
//! defined. They are initial guesses from the plan, **UNVERIFIED** until spike
//! S1 uploads a real PNG and GLB and records what the API accepts. Change the
//! table, nothing else, when S1 lands.
//!
//! Other known limits: the magic-byte checks are format sniffing, not full
//! parsing (a truncated but well-headed file passes); TGA has no signature, so
//! it is a header plausibility check; the 20 MB cap is the general limit from
//! the docs (the Video row of the guide disagrees with itself); and Mesh takes
//! Roblox-format data downloaded from the Asset Delivery API only, so no local
//! file format is accepted for it yet.
//!
//! Implementation order follows the user's priority (plan D8): Model, then
//! Image, then Audio, then Decal, Animation, Mesh, Video.

use std::fmt;
use std::path::Path;

/// General per-file upload limit from the Roblox docs (20 MB).
pub const MAX_UPLOAD_BYTES: u64 = 20 * 1024 * 1024;

/// The `assetType` values the Assets API defines, alphabetical as in the docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AssetKind {
    Animation,
    Audio,
    Decal,
    Image,
    Mesh,
    Model,
    Video,
}

impl AssetKind {
    pub const ALL: [AssetKind; 7] = [
        AssetKind::Animation,
        AssetKind::Audio,
        AssetKind::Decal,
        AssetKind::Image,
        AssetKind::Mesh,
        AssetKind::Model,
        AssetKind::Video,
    ];

    /// The exact string sent as `assetType` in the request JSON.
    pub fn api_name(self) -> &'static str {
        match self {
            AssetKind::Animation => "Animation",
            AssetKind::Audio => "Audio",
            AssetKind::Decal => "Decal",
            AssetKind::Image => "Image",
            AssetKind::Mesh => "Mesh",
            AssetKind::Model => "Model",
            AssetKind::Video => "Video",
        }
    }

    /// Case-insensitive parse of a caller-supplied asset type.
    pub fn parse(s: &str) -> Result<Self, AssetTypeError> {
        let s = s.trim();
        AssetKind::ALL
            .into_iter()
            .find(|k| k.api_name().eq_ignore_ascii_case(s))
            .ok_or_else(|| AssetTypeError::UnknownKind {
                given: s.to_string(),
            })
    }

    /// File formats this kind accepts (empty for Mesh, see the module docs).
    pub fn formats(self) -> &'static [FileFormat] {
        use FileFormat::*;
        match self {
            AssetKind::Model => &[Fbx, Gltf, Glb, Rbxm, Rbxmx],
            AssetKind::Image | AssetKind::Decal => &[Png, Jpeg, Bmp, Tga],
            AssetKind::Audio => &[Mp3, Ogg, Wav, Flac],
            AssetKind::Animation => &[Rbxm, Rbxmx],
            AssetKind::Video => &[Mp4, Mov],
            AssetKind::Mesh => &[],
        }
    }

    /// Per-kind size cap in bytes (the general 20 MB limit for every kind).
    pub fn max_bytes(self) -> u64 {
        MAX_UPLOAD_BYTES
    }

    /// Accepted extensions, for error messages.
    fn accepted_extensions(self) -> Vec<&'static str> {
        self.formats()
            .iter()
            .flat_map(|f| f.info().extensions.iter().copied())
            .collect()
    }
}

impl fmt::Display for AssetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.api_name())
    }
}

/// A concrete file format with a known extension, signature and content type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileFormat {
    Fbx,
    Glb,
    Gltf,
    Rbxm,
    Rbxmx,
    Png,
    Jpeg,
    Bmp,
    Tga,
    Mp3,
    Ogg,
    Wav,
    Flac,
    Mp4,
    Mov,
}

pub struct FormatInfo {
    pub format: FileFormat,
    /// Human-readable name for messages.
    pub label: &'static str,
    /// Lowercase extensions without the dot.
    pub extensions: &'static [&'static str],
    /// Content type sent on the `fileContent` multipart part.
    pub content_type: &'static str,
}

/// THE content-type table. UNVERIFIED until spike S1 (plan section 1.4 item 1):
/// each `content_type` is the plan's initial guess, not a recorded API answer.
/// This is the only place extensions and content types are defined.
pub const FORMAT_TABLE: [FormatInfo; 15] = [
    FormatInfo {
        format: FileFormat::Fbx,
        label: "FBX",
        extensions: &["fbx"],
        content_type: "model/fbx",
    },
    FormatInfo {
        format: FileFormat::Glb,
        label: "GLB",
        extensions: &["glb"],
        content_type: "model/gltf-binary",
    },
    FormatInfo {
        format: FileFormat::Gltf,
        label: "glTF",
        extensions: &["gltf"],
        content_type: "model/gltf+json",
    },
    FormatInfo {
        format: FileFormat::Rbxm,
        label: "RBXM",
        extensions: &["rbxm"],
        content_type: "model/x-rbxm",
    },
    FormatInfo {
        format: FileFormat::Rbxmx,
        label: "RBXMX",
        extensions: &["rbxmx"],
        content_type: "model/x-rbxm",
    },
    FormatInfo {
        format: FileFormat::Png,
        label: "PNG",
        extensions: &["png"],
        content_type: "image/png",
    },
    FormatInfo {
        format: FileFormat::Jpeg,
        label: "JPEG",
        extensions: &["jpg", "jpeg"],
        content_type: "image/jpeg",
    },
    FormatInfo {
        format: FileFormat::Bmp,
        label: "BMP",
        extensions: &["bmp"],
        content_type: "image/bmp",
    },
    FormatInfo {
        format: FileFormat::Tga,
        label: "TGA",
        extensions: &["tga"],
        content_type: "image/tga",
    },
    FormatInfo {
        format: FileFormat::Mp3,
        label: "MP3",
        extensions: &["mp3"],
        content_type: "audio/mpeg",
    },
    FormatInfo {
        format: FileFormat::Ogg,
        label: "OGG",
        extensions: &["ogg"],
        content_type: "audio/ogg",
    },
    FormatInfo {
        format: FileFormat::Wav,
        label: "WAV",
        extensions: &["wav"],
        content_type: "audio/wav",
    },
    FormatInfo {
        format: FileFormat::Flac,
        label: "FLAC",
        extensions: &["flac"],
        content_type: "audio/flac",
    },
    FormatInfo {
        format: FileFormat::Mp4,
        label: "MP4",
        extensions: &["mp4"],
        content_type: "video/mp4",
    },
    FormatInfo {
        format: FileFormat::Mov,
        label: "MOV",
        extensions: &["mov"],
        content_type: "video/quicktime",
    },
];

impl FileFormat {
    fn info(self) -> &'static FormatInfo {
        FORMAT_TABLE
            .iter()
            .find(|i| i.format == self)
            .expect("every FileFormat has a FORMAT_TABLE row")
    }

    pub fn label(self) -> &'static str {
        self.info().label
    }

    pub fn content_type(self) -> &'static str {
        self.info().content_type
    }

    /// Look up a format by extension (no dot, any case).
    pub fn from_extension(ext: &str) -> Option<Self> {
        let ext = ext.to_ascii_lowercase();
        FORMAT_TABLE
            .iter()
            .find(|i| i.extensions.contains(&ext.as_str()))
            .map(|i| i.format)
    }

    /// Does `bytes` start like this format? Signature sniffing, not parsing.
    pub fn matches(self, bytes: &[u8]) -> bool {
        match self {
            FileFormat::Png => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
            FileFormat::Jpeg => bytes.starts_with(&[0xFF, 0xD8, 0xFF]),
            FileFormat::Bmp => bytes.len() >= 26 && bytes.starts_with(b"BM"),
            FileFormat::Tga => looks_like_tga(bytes),
            FileFormat::Glb => {
                bytes.len() >= 12
                    && bytes.starts_with(b"glTF")
                    && u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) == 2
            }
            FileFormat::Gltf => looks_like_gltf_json(bytes),
            FileFormat::Fbx => bytes.starts_with(b"Kaydara FBX Binary"),
            FileFormat::Rbxm => bytes.starts_with(b"<roblox!"),
            FileFormat::Rbxmx => looks_like_rbxmx(bytes),
            FileFormat::Mp3 => {
                bytes.len() >= 4
                    && (bytes.starts_with(b"ID3") || (bytes[0] == 0xFF && bytes[1] & 0xE0 == 0xE0))
            }
            FileFormat::Ogg => bytes.starts_with(b"OggS"),
            FileFormat::Wav => {
                bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WAVE"
            }
            FileFormat::Flac => bytes.starts_with(b"fLaC"),
            FileFormat::Mp4 => has_ftyp(bytes),
            FileFormat::Mov => {
                has_ftyp(bytes)
                    || (bytes.len() >= 8
                        && [&b"moov"[..], b"mdat", b"free", b"wide", b"skip", b"pnot"]
                            .contains(&&bytes[4..8]))
            }
        }
    }
}

/// Which known format do these bytes look like? Used to explain a mismatch.
/// Strong signatures first; the weak checks (MP3 sync, TGA header) last.
pub fn sniff(bytes: &[u8]) -> Option<FileFormat> {
    use FileFormat::*;
    if has_ftyp(bytes) {
        let quicktime = &bytes[8..12] == b"qt  ";
        return Some(if quicktime { Mov } else { Mp4 });
    }
    [
        Png, Jpeg, Glb, Fbx, Rbxm, Flac, Ogg, Wav, Bmp, Mp3, Gltf, Rbxmx, Tga,
    ]
    .into_iter()
    .find(|f| f.matches(bytes))
}

fn has_ftyp(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[4..8] == b"ftyp"
}

/// TGA has no leading signature. Check the 18-byte header is plausible.
fn looks_like_tga(bytes: &[u8]) -> bool {
    if bytes.len() < 18 {
        return false;
    }
    let colour_map_type = bytes[1];
    let image_type = bytes[2];
    let width = u16::from_le_bytes([bytes[12], bytes[13]]);
    let height = u16::from_le_bytes([bytes[14], bytes[15]]);
    let depth = bytes[16];
    colour_map_type <= 1
        && matches!(image_type, 1 | 2 | 3 | 9 | 10 | 11)
        && width > 0
        && height > 0
        && matches!(depth, 8 | 15 | 16 | 24 | 32)
}

/// A `.gltf` is JSON with a top-level `asset.version` string.
fn looks_like_gltf_json(bytes: &[u8]) -> bool {
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    if body.trim_ascii_start().first() != Some(&b'{') {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .is_some_and(|v| v["asset"]["version"].is_string())
}

/// An `.rbxmx` is XML with a `<roblox ...>` root. Binary `.rbxm` is
/// `<roblox!`, so the byte after `<roblox` must be whitespace.
fn looks_like_rbxmx(bytes: &[u8]) -> bool {
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let head = &body[..body.len().min(1024)];
    let head = head.trim_ascii_start();
    let root = if head.starts_with(b"<?xml") {
        match head.windows(7).position(|w| w == b"<roblox") {
            Some(i) => &head[i..],
            None => return false,
        }
    } else {
        head
    };
    root.starts_with(b"<roblox") && root.get(7).is_some_and(|b| b.is_ascii_whitespace())
}

/// Why a file or asset type was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetTypeError {
    UnknownKind {
        given: String,
    },
    /// Mesh accepts Roblox-format data only; there is no local format yet.
    NoLocalFormat {
        kind: AssetKind,
    },
    UnsupportedExtension {
        kind: AssetKind,
        extension: String,
    },
    Empty,
    TooLarge {
        bytes: u64,
        limit: u64,
    },
    /// The extension says `expected` but the bytes do not match it.
    ContentMismatch {
        expected: FileFormat,
        detected: Option<FileFormat>,
    },
    /// Content updates currently work only for `.fbx`.
    UpdateNotSupported {
        extension: String,
    },
}

impl fmt::Display for AssetTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AssetTypeError::UnknownKind { given } => {
                let names: Vec<&str> = AssetKind::ALL.iter().map(|k| k.api_name()).collect();
                write!(
                    f,
                    "Invalid assetType '{given}'. Expected one of: {}",
                    names.join(", ")
                )?;
                if given.eq_ignore_ascii_case("ModelFromFbx") {
                    write!(f, " (use Model with a .fbx file)")?;
                } else if given.eq_ignore_ascii_case("MeshPart") {
                    write!(f, " (MeshPart is not an upload type; use Model)")?;
                }
                Ok(())
            }
            AssetTypeError::NoLocalFormat { kind } => write!(
                f,
                "{kind} uploads accept only Roblox-format data from the Asset Delivery API, so no \
                 local file is accepted yet. Upload .fbx/.glb files as Model."
            ),
            AssetTypeError::UnsupportedExtension { kind, extension } => {
                let accepted = kind
                    .accepted_extensions()
                    .iter()
                    .map(|e| format!(".{e}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                if extension.is_empty() {
                    write!(f, "The file has no extension. {kind} accepts: {accepted}")
                } else {
                    write!(
                        f,
                        "'.{extension}' is not a {kind} format. {kind} accepts: {accepted}"
                    )
                }
            }
            AssetTypeError::Empty => write!(f, "The file is empty."),
            AssetTypeError::TooLarge { bytes, limit } => write!(
                f,
                "The file is {bytes} bytes; Roblox's upload limit is {limit} bytes (20 MB)."
            ),
            AssetTypeError::ContentMismatch { expected, detected } => {
                write!(
                    f,
                    "The file extension says {} but the content is not a {} file",
                    expected.label(),
                    expected.label()
                )?;
                match detected {
                    Some(d) => write!(f, " (it looks like {}).", d.label()),
                    None => write!(f, " (unrecognised content)."),
                }
            }
            AssetTypeError::UpdateNotSupported { extension } => write!(
                f,
                "Content updates currently work only for .fbx files, not '.{extension}'. \
                 Upload it as a new asset instead."
            ),
        }
    }
}

impl std::error::Error for AssetTypeError {}

/// A file that passed every check; carries what the request builder needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedFile {
    pub kind: AssetKind,
    pub format: FileFormat,
    pub content_type: &'static str,
    pub file_name: String,
}

/// Size check usable before reading the file (from its metadata length).
pub fn validate_size(kind: AssetKind, len: u64) -> Result<(), AssetTypeError> {
    if len == 0 {
        return Err(AssetTypeError::Empty);
    }
    let limit = kind.max_bytes();
    if len > limit {
        return Err(AssetTypeError::TooLarge { bytes: len, limit });
    }
    Ok(())
}

fn extension_of(file_name: &str) -> String {
    Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

fn check_content(format: FileFormat, bytes: &[u8]) -> Result<(), AssetTypeError> {
    if format.matches(bytes) {
        Ok(())
    } else {
        Err(AssetTypeError::ContentMismatch {
            expected: format,
            detected: sniff(bytes),
        })
    }
}

fn validated(kind: AssetKind, format: FileFormat, file_name: &str) -> ValidatedFile {
    ValidatedFile {
        kind,
        format,
        content_type: format.content_type(),
        file_name: Path::new(file_name)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "asset".to_string()),
    }
}

/// Validate a file for a create (upload) request: size, extension for the kind,
/// and that the bytes match the extension.
pub fn validate_upload(
    kind: AssetKind,
    file_name: &str,
    bytes: &[u8],
) -> Result<ValidatedFile, AssetTypeError> {
    validate_size(kind, bytes.len() as u64)?;
    if kind.formats().is_empty() {
        return Err(AssetTypeError::NoLocalFormat { kind });
    }
    let extension = extension_of(file_name);
    let format = FileFormat::from_extension(&extension)
        .filter(|f| kind.formats().contains(f))
        .ok_or(AssetTypeError::UnsupportedExtension { kind, extension })?;
    check_content(format, bytes)?;
    Ok(validated(kind, format, file_name))
}

/// Validate a file for a content update of an existing asset. The docs support
/// content updates for `.fbx` only; everything else is metadata-only.
// Unused until the optional content-update step (plan step 6) comes back; the
// path-based update tool was removed because it bypassed the upload policy.
#[allow(dead_code)]
pub fn validate_content_update(
    file_name: &str,
    bytes: &[u8],
) -> Result<ValidatedFile, AssetTypeError> {
    validate_size(AssetKind::Model, bytes.len() as u64)?;
    let extension = extension_of(file_name);
    if FileFormat::from_extension(&extension) != Some(FileFormat::Fbx) {
        return Err(AssetTypeError::UpdateNotSupported { extension });
    }
    check_content(FileFormat::Fbx, bytes)?;
    Ok(validated(AssetKind::Model, FileFormat::Fbx, file_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    // (kind, file name, bytes, expected format, detected format)
    type MismatchCase = (
        AssetKind,
        &'static str,
        Vec<u8>,
        FileFormat,
        Option<FileFormat>,
    );

    // Synthetic fixtures: only the leading bytes the sniffers look at, padded.
    fn pad(mut head: Vec<u8>) -> Vec<u8> {
        head.resize(head.len().max(64), 0);
        head
    }
    fn png() -> Vec<u8> {
        pad(b"\x89PNG\r\n\x1a\n".to_vec())
    }
    fn jpeg() -> Vec<u8> {
        pad(vec![0xFF, 0xD8, 0xFF, 0xE0])
    }
    fn bmp() -> Vec<u8> {
        pad(b"BM".to_vec())
    }
    fn tga() -> Vec<u8> {
        // no colour map, uncompressed true-colour, 4x4, 24 bpp
        let mut h = vec![0u8; 18];
        h[2] = 2;
        h[12] = 4;
        h[14] = 4;
        h[16] = 24;
        pad(h)
    }
    fn glb() -> Vec<u8> {
        let mut h = b"glTF".to_vec();
        h.extend_from_slice(&2u32.to_le_bytes());
        h.extend_from_slice(&64u32.to_le_bytes());
        pad(h)
    }
    fn gltf() -> Vec<u8> {
        br#"{"asset":{"version":"2.0"},"scenes":[]}"#.to_vec()
    }
    fn fbx() -> Vec<u8> {
        pad(b"Kaydara FBX Binary  \0\x1a\0".to_vec())
    }
    fn rbxm() -> Vec<u8> {
        pad(b"<roblox!\x89\xff\r\n\x1a\n".to_vec())
    }
    fn rbxmx() -> Vec<u8> {
        br#"<roblox xmlns:xmime="http://www.w3.org/2005/05/xmlmime" version="4"></roblox>"#.to_vec()
    }
    fn mp3_id3() -> Vec<u8> {
        pad(b"ID3\x04\0".to_vec())
    }
    fn mp3_sync() -> Vec<u8> {
        pad(vec![0xFF, 0xFB, 0x90, 0x00])
    }
    fn ogg() -> Vec<u8> {
        pad(b"OggS\0".to_vec())
    }
    fn wav() -> Vec<u8> {
        pad(b"RIFF\x24\0\0\0WAVEfmt ".to_vec())
    }
    fn flac() -> Vec<u8> {
        pad(b"fLaC\0".to_vec())
    }
    fn mp4() -> Vec<u8> {
        pad(b"\0\0\0\x18ftypisom\0\0\0\0".to_vec())
    }
    fn mov() -> Vec<u8> {
        pad(b"\0\0\0\x14ftypqt  \0\0\0\0".to_vec())
    }

    #[test]
    fn accepted_files_by_kind() {
        use AssetKind as K;
        use FileFormat as F;
        // (kind, file name, bytes, expected format, expected content type)
        let cases: Vec<(K, &str, Vec<u8>, F, &str)> = vec![
            // Model (priority 1)
            (K::Model, "pet.fbx", fbx(), F::Fbx, "model/fbx"),
            (K::Model, "pet.glb", glb(), F::Glb, "model/gltf-binary"),
            (K::Model, "pet.gltf", gltf(), F::Gltf, "model/gltf+json"),
            (K::Model, "pet.rbxm", rbxm(), F::Rbxm, "model/x-rbxm"),
            (K::Model, "pet.rbxmx", rbxmx(), F::Rbxmx, "model/x-rbxm"),
            (K::Model, "PET.GLB", glb(), F::Glb, "model/gltf-binary"),
            // Image (priority 2)
            (K::Image, "a.png", png(), F::Png, "image/png"),
            (K::Image, "a.jpg", jpeg(), F::Jpeg, "image/jpeg"),
            (K::Image, "a.jpeg", jpeg(), F::Jpeg, "image/jpeg"),
            (K::Image, "a.bmp", bmp(), F::Bmp, "image/bmp"),
            (K::Image, "a.tga", tga(), F::Tga, "image/tga"),
            // Audio (priority 3)
            (K::Audio, "a.mp3", mp3_id3(), F::Mp3, "audio/mpeg"),
            (K::Audio, "a.mp3", mp3_sync(), F::Mp3, "audio/mpeg"),
            (K::Audio, "a.ogg", ogg(), F::Ogg, "audio/ogg"),
            (K::Audio, "a.wav", wav(), F::Wav, "audio/wav"),
            (K::Audio, "a.flac", flac(), F::Flac, "audio/flac"),
            // Decal, Animation, Video
            (K::Decal, "d.png", png(), F::Png, "image/png"),
            (K::Decal, "d.jpg", jpeg(), F::Jpeg, "image/jpeg"),
            (K::Animation, "a.rbxm", rbxm(), F::Rbxm, "model/x-rbxm"),
            (K::Animation, "a.rbxmx", rbxmx(), F::Rbxmx, "model/x-rbxm"),
            (K::Video, "v.mp4", mp4(), F::Mp4, "video/mp4"),
            (K::Video, "v.mov", mov(), F::Mov, "video/quicktime"),
        ];
        for (kind, name, bytes, format, content_type) in cases {
            let v = validate_upload(kind, name, &bytes)
                .unwrap_or_else(|e| panic!("{kind} {name} should pass: {e}"));
            assert_eq!(v.kind, kind, "{name}");
            assert_eq!(v.format, format, "{name}");
            assert_eq!(v.content_type, content_type, "{name}");
            assert_eq!(v.file_name, name, "{name}");
        }
    }

    #[test]
    fn every_kind_but_mesh_has_formats_and_every_format_is_reachable() {
        for kind in AssetKind::ALL {
            assert_eq!(kind.formats().is_empty(), kind == AssetKind::Mesh, "{kind}");
        }
        for info in &FORMAT_TABLE {
            assert!(
                AssetKind::ALL
                    .iter()
                    .any(|k| k.formats().contains(&info.format)),
                "{} is in no kind",
                info.label
            );
            for ext in info.extensions {
                assert_eq!(FileFormat::from_extension(ext), Some(info.format));
            }
        }
    }

    #[test]
    fn mesh_has_no_local_format() {
        let err = validate_upload(AssetKind::Mesh, "m.fbx", &fbx()).unwrap_err();
        assert_eq!(
            err,
            AssetTypeError::NoLocalFormat {
                kind: AssetKind::Mesh
            }
        );
        assert!(err.to_string().contains("Model"));
    }

    #[test]
    fn rejects_extension_not_in_kind() {
        use AssetKind as K;
        let cases: Vec<(K, &str, Vec<u8>, &str)> = vec![
            (K::Model, "pet.png", png(), "png"),
            (K::Image, "pet.fbx", fbx(), "fbx"),
            (K::Audio, "pet.png", png(), "png"),
            (K::Decal, "pet.gif", png(), "gif"),
            (K::Animation, "pet.fbx", fbx(), "fbx"),
            (K::Video, "pet.mp3", mp3_id3(), "mp3"),
            (K::Model, "pet", fbx(), ""),
        ];
        for (kind, name, bytes, ext) in cases {
            assert_eq!(
                validate_upload(kind, name, &bytes).unwrap_err(),
                AssetTypeError::UnsupportedExtension {
                    kind,
                    extension: ext.to_string()
                },
                "{kind} {name}"
            );
        }
    }

    #[test]
    fn rejects_content_that_does_not_match_the_extension() {
        use AssetKind as K;
        use FileFormat as F;
        // (kind, name, bytes, expected, detected)
        let cases: Vec<MismatchCase> = vec![
            (K::Image, "a.png", jpeg(), F::Png, Some(F::Jpeg)),
            (K::Image, "a.jpg", png(), F::Jpeg, Some(F::Png)),
            (K::Model, "a.fbx", glb(), F::Fbx, Some(F::Glb)),
            (K::Model, "a.glb", fbx(), F::Glb, Some(F::Fbx)),
            (K::Model, "a.glb", gltf(), F::Glb, Some(F::Gltf)),
            (K::Model, "a.rbxm", rbxmx(), F::Rbxm, Some(F::Rbxmx)),
            (K::Model, "a.rbxmx", rbxm(), F::Rbxmx, Some(F::Rbxm)),
            (
                K::Model,
                "a.fbx",
                b"just text, not a model".to_vec(),
                F::Fbx,
                None,
            ),
            (
                K::Model,
                "a.gltf",
                b"{\"not\":\"gltf\"}".to_vec(),
                F::Gltf,
                None,
            ),
            (K::Model, "a.gltf", b"{ broken json".to_vec(), F::Gltf, None),
            (K::Audio, "a.wav", mp3_id3(), F::Wav, Some(F::Mp3)),
            (K::Audio, "a.mp3", ogg(), F::Mp3, Some(F::Ogg)),
            (K::Audio, "a.flac", wav(), F::Flac, Some(F::Wav)),
            (
                K::Audio,
                "a.ogg",
                pad(b"RIFF\0\0\0\0AVI ".to_vec()),
                F::Ogg,
                None,
            ),
            (K::Image, "a.bmp", png(), F::Bmp, Some(F::Png)),
            (K::Image, "a.tga", pad(vec![9; 20]), F::Tga, None),
            (K::Video, "v.mp4", ogg(), F::Mp4, Some(F::Ogg)),
            (K::Video, "v.mov", png(), F::Mov, Some(F::Png)),
            (K::Animation, "a.rbxm", png(), F::Rbxm, Some(F::Png)),
            (
                K::Image,
                "a.png",
                pad(vec![0x89, b'P', b'N', b'G']),
                F::Png,
                None,
            ),
        ];
        for (kind, name, bytes, expected, detected) in cases {
            assert_eq!(
                validate_upload(kind, name, &bytes).unwrap_err(),
                AssetTypeError::ContentMismatch { expected, detected },
                "{kind} {name}"
            );
        }
    }

    #[test]
    fn mismatch_message_names_both_formats() {
        let msg = validate_upload(AssetKind::Image, "a.png", &jpeg())
            .unwrap_err()
            .to_string();
        assert!(msg.contains("PNG") && msg.contains("JPEG"), "{msg}");
    }

    #[test]
    fn rejects_empty_and_oversize() {
        for kind in AssetKind::ALL {
            assert_eq!(validate_size(kind, 0), Err(AssetTypeError::Empty), "{kind}");
            assert!(validate_size(kind, MAX_UPLOAD_BYTES).is_ok(), "{kind}");
            assert_eq!(
                validate_size(kind, MAX_UPLOAD_BYTES + 1),
                Err(AssetTypeError::TooLarge {
                    bytes: MAX_UPLOAD_BYTES + 1,
                    limit: MAX_UPLOAD_BYTES
                }),
                "{kind}"
            );
        }
        assert_eq!(
            validate_upload(AssetKind::Image, "a.png", &[]),
            Err(AssetTypeError::Empty)
        );
        let mut big = png();
        big.resize(MAX_UPLOAD_BYTES as usize + 1, 0);
        assert!(matches!(
            validate_upload(AssetKind::Image, "a.png", &big),
            Err(AssetTypeError::TooLarge { .. })
        ));
        // Exactly at the limit is still accepted.
        big.truncate(MAX_UPLOAD_BYTES as usize);
        assert!(validate_upload(AssetKind::Image, "a.png", &big).is_ok());
    }

    #[test]
    fn parses_only_the_real_api_types() {
        for kind in AssetKind::ALL {
            assert_eq!(AssetKind::parse(kind.api_name()), Ok(kind));
            assert_eq!(
                AssetKind::parse(&kind.api_name().to_ascii_lowercase()),
                Ok(kind)
            );
        }
        assert_eq!(AssetKind::parse(" Image "), Ok(AssetKind::Image));
        for bad in ["ModelFromFbx", "MeshPart", "Gif", "", "Models"] {
            assert!(
                matches!(
                    AssetKind::parse(bad),
                    Err(AssetTypeError::UnknownKind { .. })
                ),
                "{bad:?} must be rejected"
            );
        }
        let msg = AssetKind::parse("ModelFromFbx").unwrap_err().to_string();
        assert!(msg.contains("Image") && msg.contains("use Model"), "{msg}");
    }

    #[test]
    fn content_update_accepts_only_fbx() {
        let ok = validate_content_update("pet.fbx", &fbx()).unwrap();
        assert_eq!(ok.kind, AssetKind::Model);
        assert_eq!(ok.format, FileFormat::Fbx);
        assert_eq!(ok.content_type, "model/fbx");
        for (name, bytes) in [("pet.glb", glb()), ("a.png", png()), ("a.wav", wav())] {
            assert!(
                matches!(
                    validate_content_update(name, &bytes),
                    Err(AssetTypeError::UpdateNotSupported { .. })
                ),
                "{name}"
            );
        }
        assert!(matches!(
            validate_content_update("pet.fbx", &glb()),
            Err(AssetTypeError::ContentMismatch { .. })
        ));
        assert_eq!(
            validate_content_update("pet.fbx", &[]),
            Err(AssetTypeError::Empty)
        );
    }

    #[test]
    fn file_name_is_reduced_to_its_base_name() {
        let v = validate_upload(AssetKind::Image, "C:/some/dir/a.png", &png()).unwrap();
        assert_eq!(v.file_name, "a.png");
    }

    #[test]
    fn gltf_json_tolerates_bom_and_leading_whitespace() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"  \n");
        bytes.extend_from_slice(&gltf());
        assert!(validate_upload(AssetKind::Model, "a.gltf", &bytes).is_ok());
    }

    #[test]
    fn rbxmx_tolerates_xml_prolog() {
        let mut bytes = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n".to_vec();
        bytes.extend_from_slice(&rbxmx());
        assert!(validate_upload(AssetKind::Model, "a.rbxmx", &bytes).is_ok());
    }
}
