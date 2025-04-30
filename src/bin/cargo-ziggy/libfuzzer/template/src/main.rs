use libc::{c_char, c_int, size_t};
use std::ptr;

unsafe extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: size_t);
    fn LLVMFuzzerInitialize(argc: *mut c_int, argv: *mut *mut *mut c_char) -> c_int;
}
/// This file just a wrapper. It will be extracted, compiled, and started by Ziggy to fuzz an underlying `LLVMFuzzerTestOneInput`.
fn main() {
    let mut argc: c_int = 0;
    let mut argv_ptr: *mut *mut c_char = ptr::null_mut();
    let mut argv: *mut *mut *mut c_char = &mut argv_ptr;

    unsafe {
        let init_result = LLVMFuzzerInitialize(&mut argc, argv);
        if init_result != 0 {
            eprintln!(
                "[ziggy] ERROR: LLVMFuzzerInitialize returned non-zero status: {init_result}."
            );
            std::process::exit(init_result);
        }
    }

    ziggy::fuzz!(|data: &[u8]| {
        unsafe {
            LLVMFuzzerTestOneInput(data.as_ptr(), data.len() as size_t);
        }
    });
}
