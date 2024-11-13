pub fn allowed(data: &[u8]) {
    if data[0] == b'a' && data[1] == b'l' && data[2] == b'l' && data[3] == b'o' {
        println!("Wow!");
    }
}