use libc::size_t;
unsafe extern "C" {
    fn LLVMFuzzerTestOneInput(data: *const u8, size: size_t);
}

fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        unsafe {
            LLVMFuzzerTestOneInput(data.as_ptr(), data.len() as size_t);
        }
    });
}
