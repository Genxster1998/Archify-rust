use std::fs;
use std::collections::HashSet;

fn main() {
    let content = fs::read_to_string("/Users/genx/Github/archify-rust/src/app.rs").unwrap();
    let mut chars: HashSet<char> = HashSet::new();
    for c in content.chars() {
        if !c.is_ascii() {
            chars.insert(c);
        }
    }
    for c in chars {
        println!("Char: {}, Unicode: U+{:04X}", c, c as u32);
    }
}
