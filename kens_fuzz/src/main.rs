#[macro_use]
extern crate afl;

fn main() {
    fuzz!(|data: &[u8]| {
        let mut data = data.to_vec();
        if data.len() % 2 != 0 {
            data.push(0);
        }

        let encoded = kens_rs::enigma::encode(&data, false).unwrap();
        let decoded = kens_rs::enigma::decode(&encoded);

        assert_eq!(data, decoded);
    })
}