#[cfg(feature = "afl")]
pub use afl::fuzz as afl_fuzz;
#[cfg(feature = "honggfuzz")]
pub use honggfuzz::fuzz as honggfuzz_fuzz;
#[cfg(feature = "libfuzzer-sys")]
pub use libfuzzer_sys::fuzz_target as libfuzzer_fuzz;

#[macro_export]
#[cfg(feature = "afl")]
macro_rules! fuzz {
    (|$buf:ident: &[u8]| $body:block) => {
        #[no_mangle]
        fn main() {
            $crate::afl_fuzz!(|$buf| $body);
        }
    };
}

#[macro_export]
#[cfg(feature = "libfuzzer-sys")]
macro_rules! fuzz {
    (|$buf:ident: &[u8]| $body:block) => {
        $crate::libfuzzer_fuzz!(|$buf| $body);
    };
}

#[macro_export]
#[cfg(feature = "honggfuzz")]
macro_rules! fuzz {
    (|$buf:ident: &[u8]| $body:block) => {
        #[no_mangle]
        fn main() {
            loop {
                $crate::honggfuzz_fuzz!(|$buf| $body);
            }
        }
    };
}
