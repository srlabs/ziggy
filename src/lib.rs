#![doc = include_str!("../README.md")]
#[cfg(feature = "afl")]
pub use afl::fuzz as afl_fuzz;
#[cfg(feature = "honggfuzz")]
pub use honggfuzz::fuzz as honggfuzz_fuzz;

// This is our inner harness handler function for the runner.
// We open the input file and feed the data to the harness closure.
#[doc(hidden)]
#[cfg(not(any(feature = "afl", feature = "honggfuzz")))]
pub fn run_file<F>(mut closure: F)
where
    F: FnMut(&[u8]),
{
    use std::{env, fs::File, io::Read};
    let file_name: String = env::args().nth(1).expect("pass in a file name as argument");
    println!("Now running {file_name}");
    let mut buffer: Vec<u8> = Vec::new();
    let mut file = File::open(file_name).unwrap_or_else(|e| {
        eprintln!("Could not open file: {e}");
        std::process::exit(1);
    });
    file.read_to_end(&mut buffer).unwrap_or_else(|e| {
        eprintln!("Could not read file: {e}");
        std::process::exit(1);
    });
    closure(buffer.as_slice());
}

/// Fuzz a closure-like block of code by passing an object of arbitrary type.
///
/// It can handle different types of arguments for the harness closure, including Arbitrary.
///
/// See [our examples](https://github.com/srlabs/ziggy/tree/main/examples).
///
/// ```no_run
/// # fn main() {
///     ziggy::fuzz!(|data: &[u8]| {
///         if data.len() != 6 {return}
///         if data[0] != b'q' {return}
///         if data[1] != b'w' {return}
///         if data[2] != b'e' {return}
///         if data[3] != b'r' {return}
///         if data[4] != b't' {return}
///         if data[5] != b'y' {return}
///         panic!("BOOM")
///     });
/// # }
/// ```
#[macro_export]
#[cfg(not(any(feature = "afl", feature = "honggfuzz")))]
macro_rules! fuzz {
    (|$buf:ident| $body:block) => {
        $crate::run_file(|$buf| $body);
    };
    (|$buf:ident: &[u8]| $body:block) => {
        $crate::run_file(|$buf| $body);
    };
    (|$buf:ident: $dty: ty| $body:block) => {
        $crate::run_file(|$buf| {
            let $buf: $dty = {
                let mut data = ::arbitrary::Unstructured::new($buf);
                if let Ok(d) = ::arbitrary::Arbitrary::arbitrary(&mut data).map_err(|_| "") {
                    d
                } else {
                    return;
                }
            };
            $body
        });
    };
}

#[macro_export]
#[cfg(feature = "afl")]
macro_rules! fuzz {
    ( $($x:tt)* ) => {
        $crate::afl_fuzz!($($x)*);
    };
}

#[macro_export]
#[cfg(feature = "honggfuzz")]
macro_rules! fuzz {
    ( $($x:tt)* ) => {
        loop {
            $crate::honggfuzz_fuzz!($($x)*);
        }
    };
}
