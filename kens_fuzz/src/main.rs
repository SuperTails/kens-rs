#[macro_use]
extern crate afl;

fn main() {
    /*fuzz!(|data: &[u8]| {
        let mut data = data.to_vec();
        if data.len() % 2 != 0 {
            data.push(0);
        }

        let encoded = kens_rs::enigma::encode(&data, false).unwrap();
        let decoded = kens_rs::enigma::decode(&encoded);

        assert_eq!(data, decoded);
    });

    fuzz!(|data: &[u8]| {
        let mut data = data.to_vec();
        for _ in 0..0x20 - (data.len() % 0x20) {
            data.push(0);
        }
        let data = data;

        let encoded = kens_rs::nemesis::encode(&data).unwrap();
        let mut decoded = Vec::new();
        kens_rs::nemesis::decode(&mut &encoded[..], &mut decoded);

        assert_eq!(data, decoded);
    });*/

    fuzz!(|data: &[u8]| {
        {
            let mut data = data.to_vec();
            if data.len() % 2 != 0 {
                data.push(0);
            }

            {
                let encoded = kens_rs::kosinski::encode_default(&data, false).unwrap();
                let decoded = kens_rs::kosinski::decode(&encoded, false).unwrap();

                assert_eq!(data, decoded);
            }
        }
    });
}