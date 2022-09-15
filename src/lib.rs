#[cfg(feature = "afl")]
pub use afl::fuzz as afl_fuzz;
#[cfg(feature = "honggfuzz")]
pub use honggfuzz::fuzz as honggfuzz_fuzz;
#[cfg(feature = "libfuzzer-sys")]
pub use libfuzzer_sys::fuzz_target as libfuzzer_fuzz;

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
#[cfg(feature = "libfuzzer-sys")]
macro_rules! fuzz {
    ( $($x:tt)* ) => {
        $crate::libfuzzer_fuzz!($($x)*);
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
