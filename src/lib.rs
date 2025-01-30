#![doc = include_str!("../README.md")]
#[cfg(feature = "afl")]
pub use afl::fuzz as afl_fuzz;
#[cfg(feature = "coverage")]
pub use fork;
#[cfg(feature = "honggfuzz")]
pub use honggfuzz::fuzz as honggfuzz_fuzz;

// This is our inner harness handler function for the runner.
// We open the input file and feed the data to the harness closure.
#[doc(hidden)]
pub fn read_file_and_fuzz<F>(mut closure: F, file: String)
where
    F: FnMut(&[u8]),
{
    use std::{fs::File, io::Read};
    println!("Now running file {file}");
    let mut buffer: Vec<u8> = Vec::new();
    match File::open(file) {
        Ok(mut f) => {
            match f.read_to_end(&mut buffer) {
                Ok(_) => {
                    closure(buffer.as_slice());
                }
                Err(e) => {
                    println!("Could not get data from file: {e}");
                }
            };
        }
        Err(e) => {
            println!("Error opening file: {e}");
        }
    };
}

// This is our special coverage harness runner.
// We open the input file and feed the data to the harness closure.
// The difference with the runner is that we catch any kind of panic.
#[cfg(feature = "coverage")]
pub fn read_file_and_fuzz<F>(mut closure: F, file: String)
where
    F: FnMut(&[u8]),
{
    use std::{fs::File, io::Read, process::exit};
    println!("Now running file {file} for coverage");
    let mut buffer: Vec<u8> = Vec::new();
    match File::open(file) {
        Ok(mut f) => {
            match f.read_to_end(&mut buffer) {
                Ok(_) => {
                    use crate::fork::{fork, Fork};

                    match fork() {
                        Ok(Fork::Parent(child)) => {
                            println!(
                                "Continuing execution in parent process, new child has pid: {}",
                                child
                            );
                            unsafe {
                                let mut status = 0i32;
                                let _ = libc::waitpid(child, &mut status, 0);
                            }
                            println!("Child is done, moving on");
                        }
                        Ok(Fork::Child) => {
                            closure(buffer.as_slice());
                            exit(0);
                        }
                        Err(_) => println!("Fork failed"),
                    }
                }
                Err(e) => {
                    println!("Could not get data from file: {e}");
                }
            };
        }
        Err(e) => {
            println!("Error opening file: {e}");
        }
    };
}

// This is our middle harness handler macro for the runner and for coverage.
// We read input files and directories from the command line and run the inner harness `fuzz`.
#[doc(hidden)]
#[macro_export]
macro_rules! read_args_and_fuzz {
    ( |$buf:ident| $body:block ) => {
        use std::{env, fs};
        let args: Vec<String> = env::args().collect();
        for path in &args[1..] {
            if let Ok(metadata) = fs::metadata(&path) {
                let files = match metadata.is_dir() {
                    true => fs::read_dir(&path)
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
                println!("Finished reading all files");
            } else {
                println!("Could not read metadata for {path}");
            }
        }
    };
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
macro_rules! inner_fuzz {
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

/// We need this wrapper
#[macro_export]
#[cfg(not(any(feature = "afl", feature = "honggfuzz")))]
macro_rules! fuzz {
    ( $($x:tt)* ) => {
        $crate::inner_fuzz!($($x)*);
    }
}

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

#[macro_export]
#[cfg(feature = "honggfuzz")]
macro_rules! fuzz {
    ( $($x:tt)* ) => {
        loop {
            $crate::honggfuzz_fuzz!($($x)*);
        }
    };
}
