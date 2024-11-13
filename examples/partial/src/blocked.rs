pub fn blocked(data: &[u8]) {
    if data[0] == b'b' && data[1] == b'l' && data[2] == b'o' && data[3] == b'c' {
        panic!("This was blocked");
    }
}