#![no_main]

ziggy::fuzz!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = url::Url::parse(&s);
    }
});
