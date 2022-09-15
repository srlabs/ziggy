#![no_main]

lazy_static::lazy_static! {
    static ref CRASH_STRINGS: Vec<String> = vec![
        "bananaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        "mangoaaaaaaaaaaaaaaaaaaaa".into(),
        "pineappleaaaaaaaaaaaaaaaaaaaa".into(),
    ];
}

ziggy::fuzz!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        for crash_string in CRASH_STRINGS.iter() {
            if s == crash_string {
                panic!("Found a {}", crash_string);
            }
        }
    }
});
