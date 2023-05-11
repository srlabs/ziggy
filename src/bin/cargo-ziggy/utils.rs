// Stringify an integer
// Inspired by AFL++
// https://github.com/AFLplusplus/AFLplusplus/blob/74be9ab5ce61d5b561faf688c245143da1a0141e/src/afl-common.c#L1140-L1196
pub fn stringify_integer(value: u64) -> String {
    match value {
        0..=9_999 => format!("{value}"),
        10_000..=99_999 => format!("{:0.01}k", value as f64 / 1_000f64),
        100_000..=999_999 => format!("{}k", value / 1_000),
        1_000_000..=9_999_999 => format!("{:0.02}M", value as f64 / 1_000_000f64),
        10_000_000..=99_999_999 => format!("{:0.01}M", value as f64 / 1_000_000f64),
        100_000_000..=999_999_999 => format!("{}M", value / 1_000_000),
        1_000_000_000..=9_999_999_999 => format!("{:0.02}G", value as f64 / 1_000_000_000f64),
        10_000_000_000..=99_999_999_999 => format!("{:0.01}G", value as f64 / 1_000_000_000f64),
        100_000_000_000..=999_999_999_999 => format!("{}G", value / 1_000_000_000),
        1_000_000_000_000..=9_999_999_999_999 => {
            format!("{:0.02}T", value as f64 / 1_000_000_000_000f64)
        }
        10_000_000_000_000..=99_999_999_999_999 => {
            format!("{:0.01}T", value as f64 / 1_000_000_000_000f64)
        }
        _ => format!("infty"),
    }
}
