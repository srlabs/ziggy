mod blocked;
mod allowed;
mod other;

fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        if data.len() < 4 {
            return
        }
        allowed::allowed(&data);
        blocked::blocked(&data);
        other::other(&data);
    });
}
