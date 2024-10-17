fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        if data.len() < 4 {
            return 
        }
        if data[0] == b'f' {
            if data[1] == b'u' {
                if data[2] == b'z' {
                    if data[3] == b'z' {
                        let xs = [0, 1, 2, 3];
                        let _y = unsafe { *xs.as_ptr().offset(4) };
                    }
                }
            }
        }
    });
}
