#[cfg(feature = "afl")]
pub use afl::fuzz as afl_fuzz;
#[cfg(feature = "honggfuzz")]
pub use honggfuzz::fuzz as honggfuzz_fuzz;

// This is our inner harness handler function for the runner and for coverage.
// We open the input file and feed the data to the harness closure.
#[cfg(not(any(feature = "afl", feature = "honggfuzz")))]
pub fn read_file_and_fuzz<F>(mut closure: F, file: String)
where
    F: FnMut(&[u8]),
{
    println!("Now running file {file}");
    use std::{fs::File, io::Read};
    let mut buffer: Vec<u8> = Vec::new();
    let mut f = File::open(file).unwrap();
    f.read_to_end(&mut buffer).unwrap();
    closure(buffer.as_slice());
}

// This is our middle harness handler macro for the runner and for coverage.
// We read input files and directories from the command line and run the inner harness `fuzz`.
#[macro_export]
#[cfg(not(any(feature = "afl", feature = "honggfuzz")))]
macro_rules! read_args_and_fuzz {
    ( |$buf:ident| $body:block ) => {
        #[no_mangle]
        fn main() {
            let args: Vec<String> = std::env::args().collect();
            for path in &args[1..] {
                if let Ok(metadata) = std::fs::metadata(&path) {
                    let files = match metadata.is_dir() {
                        true => std::fs::read_dir(&path)
                            .unwrap()
                            .map(|x| x.unwrap().path())
                            .filter(|x| x.is_file())
                            .map(|x| x.to_str().unwrap().to_string())
                            .collect::<Vec<String>>(),
                        false => vec![path.to_string()],
                    };

                    for file in files {
                        $crate::read_file_and_fuzz(|$buf| $body, file);
                    }
                } else {
                    println!("Could not read metadata for {path}");
                }
            }
        }
    };
}

// This is our outer harness handler macro for the runner and for coverage.
// It is used to handle different types of arguments for the harness closure, including Arbitrary.
#[macro_export]
#[cfg(not(any(feature = "afl", feature = "honggfuzz")))]
macro_rules! fuzz {
    (|$buf:ident| $body:block) => {
        $crate::read_args_and_fuzz!(|$buf| $body);
    };
    (|$buf:ident: &[u8]| $body:block) => {
        $crate::read_args_and_fuzz!(|$buf| $body);
    };
    (|$buf:ident: $dty: ty| $body:block) => {
        $crate::read_args_and_fuzz!(|$buf| {
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
        #[no_mangle]
        fn main() {
            $crate::afl_fuzz!($($x)*);
        }
    };
}

#[macro_export]
#[cfg(feature = "honggfuzz")]
macro_rules! fuzz {
    ( $($x:tt)* ) => {
        #[no_mangle]
        fn main() {
            loop {
                $crate::honggfuzz_fuzz!($($x)*);
            }
        }
    };
}
