// This example demonstrates non-deterministic behavior that causes AFL++
// to report sub-100% stability. The harness uses system randomness to choose
// between different code branches, so the same input triggers different
// execution paths on different runs.

fn process(data: &[u8]) {
    if data.len() < 4 {
        return;
    }

    // Deterministic branch: always taken for inputs starting with 'A'
    if data[0] == b'A' {
        let _sum: u32 = data.iter().map(|b| *b as u32).sum();
    }

    // NON-DETERMINISTIC: use system randomness to choose a code path.
    // This is the kind of instability that AFL++ detects: the same input
    // will exercise different edges depending on the random value.
    let random_byte = get_random_byte();

    match random_byte % 4 {
        0 => {
            // Path A: treat data as length-prefixed
            let len = data[0] as usize;
            let _ = data.get(1..1 + len);
        }
        1 => {
            // Path B: treat data as key-value with '=' separator
            for window in data.windows(1) {
                if window[0] == b'=' {
                    break;
                }
            }
        }
        2 => {
            // Path C: compute a checksum
            let mut checksum: u8 = 0;
            for byte in data {
                checksum = checksum.wrapping_add(*byte);
            }
            let _ = checksum;
        }
        3 => {
            // Path D: scan for null terminator
            for byte in data {
                if *byte == 0 {
                    break;
                }
            }
        }
        _ => unreachable!(),
    }

    // Another non-deterministic branch: random coin flip
    if get_random_byte() > 127 {
        // "Encrypt" path
        let _encrypted: Vec<u8> = data.iter().map(|b| b.wrapping_add(13)).collect();
    } else {
        // "Hash" path
        let mut hash: u64 = 5381;
        for byte in data {
            hash = hash.wrapping_mul(33).wrapping_add(*byte as u64);
        }
        let _ = hash;
    }
}

/// Read a single random byte from the OS.
fn get_random_byte() -> u8 {
    use std::fs::File;
    use std::io::Read;
    let mut buf = [0u8; 1];
    File::open("/dev/urandom")
        .expect("failed to open /dev/urandom")
        .read_exact(&mut buf)
        .expect("failed to read from /dev/urandom");
    buf[0]
}

fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        process(data);
    });
}
