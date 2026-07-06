use ttf_parser::Face;
use std::fs;

fn main() {
    let noto_bytes = fs::read("/tmp/egui/crates/epaint_default_fonts/fonts/NotoEmoji-Regular.ttf").unwrap();
    let ubuntu_bytes = fs::read("/tmp/egui/crates/epaint_default_fonts/fonts/Ubuntu-Light.ttf").unwrap();
    let hack_bytes = fs::read("/tmp/egui/crates/epaint_default_fonts/fonts/Hack-Regular.ttf").unwrap();
    let emoji_icon_bytes = fs::read("/tmp/egui/crates/epaint_default_fonts/fonts/emoji-icon-font.ttf").unwrap();

    let noto = Face::parse(&noto_bytes, 0).unwrap();
    let ubuntu = Face::parse(&ubuntu_bytes, 0).unwrap();
    let hack = Face::parse(&hack_bytes, 0).unwrap();
    let emoji_icon = Face::parse(&emoji_icon_bytes, 0).unwrap();

    let chars = vec!['★', '❌', '📱', 'ⓘ', '✓', '•', '🔗', '↻', '💻', '×', '🖹', '⚠', '©'];

    for c in chars {
        let mut found = Vec::new();
        if noto.glyph_index(c).is_some() { found.push("NotoEmoji"); }
        if ubuntu.glyph_index(c).is_some() { found.push("Ubuntu"); }
        if hack.glyph_index(c).is_some() { found.push("Hack"); }
        if emoji_icon.glyph_index(c).is_some() { found.push("emoji-icon-font"); }
        
        println!("Char: {}, Supported by: {:?}", c, found);
    }
}
