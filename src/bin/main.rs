const DATA: &[u8; 244] =
    include_bytes!("/home/salix/Documents/Rust/megarust/roms/s1disasm/artnem/Rings.bin");

fn main() {
    let mut decompressed = Vec::new();
    kens_sys::nemesis::decode(&mut &DATA[..], &mut decompressed);

    println!("{:#X} bytes of data:", decompressed.len(),);
    print!("[");
    for d in decompressed.iter() {
        print!("{:#04X}, ", d);
    }
    println!("]");

    println!("Chunks:");
    for c in decompressed.chunks(0x20) {
        print!("[");
        for c in c {
            print!("{:02X}, ", c);
        }
        println!("]")
    }

    for tile in decompressed.chunks(0x20) {
        for row in 0..8 {
            for col in 0..8 {
                let raw = tile[row * 4 + col / 2];

                let data = if col % 2 == 0 { raw >> 4 } else { raw & 0xF };
                if data == 0 {
                    print!(".");
                } else {
                    print!("{:X}", data);
                }
            }
            println!();
        }
        println!();
    }
}