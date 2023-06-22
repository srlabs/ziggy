fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        if let Ok(s) = std::str::from_utf8(data) {
            if let Ok(parsed) = url::Url::parse(s) {
                #[cfg(not(fuzzing))]
                println!("parsed:\t{parsed}");
                let as_str = parsed.as_str();
                #[cfg(not(fuzzing))]
                println!("as_str:\t{as_str}");
                assert_eq!(parsed, url::Url::parse(as_str).unwrap());
            }
        }
    });
}
