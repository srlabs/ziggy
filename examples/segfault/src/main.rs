fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        unsafe { std::ptr::null_mut::<i32>().write(data[0] as i32) };
    });
}
