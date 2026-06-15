//! Test-only synthesis of crisp bitmap-text images from the embedded font.
//!
//! Rendering with the *same* templates the recogniser matches against lets the
//! OCR path be exercised end-to-end (render → decode → recognise) without
//! committing binary image fixtures to the tree. The layout mirrors exactly the
//! grid the recogniser assumes: integer `scale`, a `GLYPH_W`-wide cell followed
//! by one blank `scale`-wide column group (so `period = 6 * scale`), lines
//! stacked top-to-bottom with a one-`scale` blank separator.

use super::font::{self, GLYPH_H, GLYPH_W};

/// Render a single line of text to an 8-bit grayscale PNG at the given scale.
pub(crate) fn render_line_png(text: &str, scale: usize) -> Vec<u8> {
    render_lines_png(&[text], scale)
}

/// Render several stacked lines to an 8-bit grayscale PNG.
pub(crate) fn render_lines_png(lines: &[&str], scale: usize) -> Vec<u8> {
    let scale = scale.max(1);
    let cell_w = GLYPH_W * scale;
    let period = cell_w + scale;
    let cell_h = GLYPH_H * scale;
    let line_advance = cell_h + scale;

    let max_cells = lines.iter().map(|l| l.chars().count()).max().unwrap_or(0);
    let width = (max_cells * period).max(1);
    let height = (lines.len() * line_advance).saturating_sub(scale).max(1);

    let mut luma = vec![255u8; width * height];
    for (li, line) in lines.iter().enumerate() {
        let y_off = li * line_advance;
        for (ci, ch) in line.chars().enumerate() {
            let x_off = ci * period;
            let Some(glyph) = font::lookup(ch) else {
                continue; // space / unsupported → blank cell
            };
            for (gy, &row) in glyph.rows.iter().enumerate() {
                for gx in 0..GLYPH_W {
                    if (row >> (GLYPH_W - 1 - gx)) & 1 == 1 {
                        paint_block(&mut luma, width, height, x_off + gx * scale, y_off + gy * scale, scale);
                    }
                }
            }
        }
    }
    encode_png_gray(&luma, width, height)
}

fn paint_block(luma: &mut [u8], width: usize, height: usize, x0: usize, y0: usize, scale: usize) {
    for dy in 0..scale {
        for dx in 0..scale {
            let x = x0 + dx;
            let y = y0 + dy;
            if x < width && y < height && let Some(slot) = luma.get_mut(y * width + x) {
                *slot = 0;
            }
        }
    }
}

fn encode_png_gray(luma: &[u8], width: usize, height: usize) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width as u32, height as u32);
        encoder.set_color(png::ColorType::Grayscale);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().expect("png header");
        writer.write_image_data(luma).expect("png image data");
    }
    out
}
