#![no_main]

// TODO find a way to have complex static variables, like with lazy_static
/*
lazy_static! {
    static ref MY_VAR: Vec<uint> = vec![
        1,
        3,
        3,
        7,
    ];
}
*/

ziggy::fuzz!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = url::Url::parse(&s);
    }
});
