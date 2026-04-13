#![doc = include_str!("../README.md")]

// This is our inner harness handler function for the runner.
// We open the input file and feed the data to the harness closure.
#[doc(hidden)]
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

/// Fuzz a closure-like block of code by passing a slice or an object of arbitrary type.
///
/// It can handle different types of arguments for the harness closure, including [`Arbitrary`](https://docs.rs/arbitrary/latest/arbitrary/trait.Arbitrary.html).
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
#[doc(hidden)]
macro_rules! inner_fuzz {
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

#[cfg(not(any(feature = "afl", feature = "honggfuzz")))]
#[doc(inline)]
pub use inner_fuzz as fuzz;

#[cfg(feature = "afl")]
#[doc(hidden)]
pub use afl::fuzz as afl_fuzz;

#[macro_export]
#[cfg(feature = "afl")]
macro_rules! fuzz {
      ( $($x:tt)* ) => {
        static USE_ARGS: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| std::env::args().len() > 1);
        if *USE_ARGS {
            $crate::inner_fuzz!($($x)*);
        } else {
            $crate::afl_fuzz!($($x)*);
        }
    };
}

#[cfg(all(feature = "honggfuzz", not(feature = "afl")))]
#[doc(inline)]
pub use honggfuzz::fuzz;
