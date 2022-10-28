#![no_main]

ziggy::fuzz!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(_parsed) = url::Url::parse(&s) {
            #[cfg(not(fuzzing))]
            println!("{_parsed}");
        }
    }
});
