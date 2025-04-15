use libc::size_t;
unsafe extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: size_t);
}
/// This file just a wrapper. It will be extracted, compiled, and started by Ziggy to fuzz an underlying `LLVMFuzzerTestOneInput`.
fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        unsafe {
            LLVMFuzzerTestOneInput(data.as_ptr(), data.len() as size_t);
        }
    });
}
