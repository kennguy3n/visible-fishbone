//! Image decoding for the OCR engine.
//!
//! Every decoder converts to a single [`GrayImage`] (8-bit luma, `0` = black
//! ink, `255` = white paper) and enforces the caller's dimension caps *before*
//! allocating pixel storage, so a malformed or hostile header can never trigger
//! an unbounded allocation. PNG is delegated to the `png` crate (configured
//! with an explicit byte budget); BMP and the Netpbm family are parsed by the
//! small, allocation-conscious readers below.

/// Decoded 8-bit grayscale raster, row-major, `0` = ink … `255` = background.
#[derive(Clone, Debug)]
pub(crate) struct GrayImage {
    pub width: usize,
    pub height: usize,
    pub luma: Vec<u8>,
}

/// Why a buffer could not be turned into a [`GrayImage`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// The magic bytes matched no supported decoder.
    Unsupported,
    /// The header parsed but the payload was truncated or self-inconsistent.
    Malformed,
    /// The declared dimensions exceed the caller's caps.
    Oversized,
}

/// Recognised container formats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImageFormat {
    Png,
    Bmp,
    Netpbm,
}

/// Cheap magic-byte sniff. Returns `None` for anything we do not decode so the
/// caller can skip non-image content without paying for a parse attempt.
pub(crate) fn sniff(bytes: &[u8]) -> Option<ImageFormat> {
    const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    if bytes.len() >= 8 && bytes[..8] == PNG_MAGIC {
        return Some(ImageFormat::Png);
    }
    if bytes.len() >= 2 && &bytes[..2] == b"BM" {
        return Some(ImageFormat::Bmp);
    }
    if bytes.len() >= 2 && bytes[0] == b'P' && matches!(bytes[1], b'2' | b'3' | b'5' | b'6') {
        return Some(ImageFormat::Netpbm);
    }
    None
}

/// Decode `bytes` into a [`GrayImage`], rejecting anything whose dimensions
/// breach `max_dimension` (per side) or `max_pixels` (total).
pub(crate) fn decode(
    bytes: &[u8],
    max_dimension: usize,
    max_pixels: usize,
) -> Result<GrayImage, DecodeError> {
    match sniff(bytes) {
        Some(ImageFormat::Png) => decode_png(bytes, max_dimension, max_pixels),
        Some(ImageFormat::Bmp) => decode_bmp(bytes, max_dimension, max_pixels),
        Some(ImageFormat::Netpbm) => decode_netpbm(bytes, max_dimension, max_pixels),
        None => Err(DecodeError::Unsupported),
    }
}

/// Rec. 601 luma, computed in fixed point to avoid floats on the decode path.
fn rgb_to_luma(r: u8, g: u8, b: u8) -> u8 {
    let y = 77 * u32::from(r) + 150 * u32::from(g) + 29 * u32::from(b);
    u8::try_from((y >> 8) & 0xff).unwrap_or(0)
}

/// Reject dimensions that are zero or exceed the caps, before any allocation.
fn check_dims(
    width: u64,
    height: u64,
    max_dimension: usize,
    max_pixels: usize,
) -> Result<(usize, usize), DecodeError> {
    if width == 0 || height == 0 {
        return Err(DecodeError::Malformed);
    }
    let max_dim = max_dimension as u64;
    if width > max_dim || height > max_dim {
        return Err(DecodeError::Oversized);
    }
    let pixels = width.saturating_mul(height);
    if pixels > max_pixels as u64 {
        return Err(DecodeError::Oversized);
    }
    // The cap checks above guarantee these conversions cannot truncate, but we
    // still go through `try_from` so a 32-bit target degrades to a graceful
    // skip instead of a silent wrap.
    let width = usize::try_from(width).map_err(|_| DecodeError::Oversized)?;
    let height = usize::try_from(height).map_err(|_| DecodeError::Oversized)?;
    Ok((width, height))
}

fn decode_png(
    bytes: &[u8],
    max_dimension: usize,
    max_pixels: usize,
) -> Result<GrayImage, DecodeError> {
    // Bound the decoder's own scratch allocations as defence-in-depth against a
    // decompression bomb, in addition to the dimension caps below.
    let alloc_budget = max_pixels.saturating_mul(4).saturating_add(1 << 20);
    let mut decoder = png::Decoder::new_with_limits(
        bytes,
        png::Limits {
            bytes: alloc_budget,
        },
    );
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().map_err(|_| DecodeError::Malformed)?;

    let (width, height) = {
        let info = reader.info();
        check_dims(
            u64::from(info.width),
            u64::from(info.height),
            max_dimension,
            max_pixels,
        )?
    };

    let mut buf = vec![0u8; reader.output_buffer_size()];
    let frame = reader
        .next_frame(&mut buf)
        .map_err(|_| DecodeError::Malformed)?;
    let channels = match frame.color_type {
        png::ColorType::Grayscale => 1usize,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        // EXPAND in `normalize_to_color8` turns Indexed into Rgb(a); reaching
        // this arm means the frame disagreed with the header.
        png::ColorType::Indexed => return Err(DecodeError::Malformed),
    };

    let data = buf
        .get(..frame.line_size * height)
        .ok_or(DecodeError::Malformed)?;
    let mut luma = Vec::with_capacity(width * height);
    for row in data.chunks_exact(frame.line_size) {
        let pixels = row.get(..width * channels).ok_or(DecodeError::Malformed)?;
        for px in pixels.chunks_exact(channels) {
            let value = if channels >= 3 {
                rgb_to_luma(px[0], px[1], px[2])
            } else {
                px[0]
            };
            luma.push(value);
        }
    }
    Ok(GrayImage {
        width,
        height,
        luma,
    })
}

fn read_u16_le(bytes: &[u8], at: usize) -> Option<u16> {
    let slice = bytes.get(at..at + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn read_i32_le(bytes: &[u8], at: usize) -> Option<i32> {
    read_u32_le(bytes, at).map(u32::cast_signed)
}

/// Decode an uncompressed (`BI_RGB`) Windows BMP: 8-bit palette, 24-bit BGR, or
/// 32-bit BGRA. Both bottom-up and top-down row orders are honoured.
fn decode_bmp(
    bytes: &[u8],
    max_dimension: usize,
    max_pixels: usize,
) -> Result<GrayImage, DecodeError> {
    let pixel_offset = read_u32_le(bytes, 10).ok_or(DecodeError::Malformed)? as usize;
    let header_size = read_u32_le(bytes, 14).ok_or(DecodeError::Malformed)?;
    if header_size < 40 {
        return Err(DecodeError::Unsupported);
    }
    let raw_w = read_i32_le(bytes, 18).ok_or(DecodeError::Malformed)?;
    let raw_h = read_i32_le(bytes, 22).ok_or(DecodeError::Malformed)?;
    let bpp = read_u16_le(bytes, 28).ok_or(DecodeError::Malformed)?;
    let compression = read_u32_le(bytes, 30).ok_or(DecodeError::Malformed)?;
    if compression != 0 {
        return Err(DecodeError::Unsupported);
    }
    let top_down = raw_h < 0;
    if raw_w <= 0 {
        return Err(DecodeError::Malformed);
    }
    // A negative height encodes a top-down row order; magnitude is the height.
    let (width, height) = check_dims(
        u64::from(raw_w.unsigned_abs()),
        u64::from(raw_h.unsigned_abs()),
        max_dimension,
        max_pixels,
    )?;

    // Palette (8-bit only): BGRA quads sitting between the DIB header and the
    // pixel array.
    let palette_start = 14 + header_size as usize;
    let palette = if bpp == 8 {
        let count = (pixel_offset.saturating_sub(palette_start)) / 4;
        let mut entries = Vec::with_capacity(count.min(256));
        for i in 0..count.min(256) {
            let at = palette_start + i * 4;
            let quad = bytes.get(at..at + 4).ok_or(DecodeError::Malformed)?;
            entries.push(rgb_to_luma(quad[2], quad[1], quad[0]));
        }
        Some(entries)
    } else if bpp == 24 || bpp == 32 {
        None
    } else {
        return Err(DecodeError::Unsupported);
    };

    let bytes_per_pixel = (bpp / 8) as usize;
    let row_stride = (width * bytes_per_pixel).div_ceil(4) * 4; // padded to 4 bytes
    let pixels_end = pixel_offset
        .checked_add(
            row_stride
                .checked_mul(height)
                .ok_or(DecodeError::Malformed)?,
        )
        .ok_or(DecodeError::Malformed)?;
    let raster = bytes
        .get(pixel_offset..pixels_end)
        .ok_or(DecodeError::Malformed)?;

    let mut luma = vec![0u8; width * height];
    for src_row in 0..height {
        let dst_row = if top_down {
            src_row
        } else {
            height - 1 - src_row
        };
        let row = raster
            .get(src_row * row_stride..src_row * row_stride + width * bytes_per_pixel)
            .ok_or(DecodeError::Malformed)?;
        for (x, px) in row.chunks_exact(bytes_per_pixel).enumerate() {
            let value = match (bpp, &palette) {
                (8, Some(pal)) => *pal.get(px[0] as usize).unwrap_or(&0),
                (24 | 32, _) => rgb_to_luma(px[2], px[1], px[0]),
                _ => return Err(DecodeError::Unsupported),
            };
            if let Some(slot) = luma.get_mut(dst_row * width + x) {
                *slot = value;
            }
        }
    }
    Ok(GrayImage {
        width,
        height,
        luma,
    })
}

/// Minimal Netpbm reader covering P2/P3 (ASCII) and P5/P6 (binary) with a
/// `maxval` of at most 255. Comments (`# …`) in the header are skipped.
fn decode_netpbm(
    bytes: &[u8],
    max_dimension: usize,
    max_pixels: usize,
) -> Result<GrayImage, DecodeError> {
    let magic = bytes.get(..2).ok_or(DecodeError::Malformed)?;
    let (ascii, channels) = match magic {
        b"P2" => (true, 1usize),
        b"P3" => (true, 3),
        b"P5" => (false, 1),
        b"P6" => (false, 3),
        _ => return Err(DecodeError::Unsupported),
    };

    let mut cursor = 2usize;
    let width = next_header_uint(bytes, &mut cursor)?;
    let height = next_header_uint(bytes, &mut cursor)?;
    let maxval = next_header_uint(bytes, &mut cursor)?;
    if maxval == 0 || maxval > 255 {
        return Err(DecodeError::Unsupported);
    }
    let (width, height) = check_dims(
        u64::from(width),
        u64::from(height),
        max_dimension,
        max_pixels,
    )?;

    let mut luma = Vec::with_capacity(width * height);
    if ascii {
        // A single shared cursor walks the remaining whitespace-separated ints.
        for _ in 0..width * height {
            let value = if channels == 1 {
                next_header_uint(bytes, &mut cursor)?
            } else {
                let r = next_header_uint(bytes, &mut cursor)?;
                let g = next_header_uint(bytes, &mut cursor)?;
                let b = next_header_uint(bytes, &mut cursor)?;
                u32::from(rgb_to_luma(clamp_u8(r), clamp_u8(g), clamp_u8(b)))
            };
            luma.push(clamp_u8(value));
        }
    } else {
        // Exactly one whitespace byte separates the header from binary samples.
        let data = bytes.get(cursor + 1..).ok_or(DecodeError::Malformed)?;
        let needed = width * height * channels;
        let data = data.get(..needed).ok_or(DecodeError::Malformed)?;
        for px in data.chunks_exact(channels) {
            let value = if channels == 1 {
                px[0]
            } else {
                rgb_to_luma(px[0], px[1], px[2])
            };
            luma.push(value);
        }
    }
    Ok(GrayImage {
        width,
        height,
        luma,
    })
}

fn clamp_u8(value: u32) -> u8 {
    u8::try_from(value.min(255)).unwrap_or(255)
}

/// Read the next unsigned integer from a Netpbm header/body, skipping ASCII
/// whitespace and `#`-to-end-of-line comments. Advances `cursor` past it.
fn next_header_uint(bytes: &[u8], cursor: &mut usize) -> Result<u32, DecodeError> {
    loop {
        match bytes.get(*cursor) {
            Some(b'#') => {
                while let Some(&c) = bytes.get(*cursor) {
                    *cursor += 1;
                    if c == b'\n' {
                        break;
                    }
                }
            }
            Some(c) if c.is_ascii_whitespace() => *cursor += 1,
            Some(_) => break,
            None => return Err(DecodeError::Malformed),
        }
    }
    let start = *cursor;
    let mut value: u32 = 0;
    let mut seen = false;
    while let Some(&c) = bytes.get(*cursor) {
        if c.is_ascii_digit() {
            value = value.saturating_mul(10).saturating_add(u32::from(c - b'0'));
            seen = true;
            *cursor += 1;
        } else {
            break;
        }
    }
    if !seen || *cursor == start {
        return Err(DecodeError::Malformed);
    }
    Ok(value)
}
