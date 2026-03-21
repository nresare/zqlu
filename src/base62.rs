use codeckit::Base62 as UpstreamBase62;

pub fn encode(input: &[u8]) -> String {
    let leading_zeroes = input.iter().take_while(|&&x| x == 0).count();
    if leading_zeroes == 0 {
        return UpstreamBase62::encode(input);
    }

    let rest = &input[leading_zeroes..];
    let rest = if rest.is_empty() {
        String::new()
    } else {
        UpstreamBase62::encode(rest)
    };

    format!("{}{}", "0".repeat(leading_zeroes), rest)
}

pub fn decode(input: &str) -> Vec<u8> {
    let leading_zeroes = input.bytes().take_while(|&x| x == b'0').count();
    let rest = &input[leading_zeroes..];
    let mut out = vec![0; leading_zeroes];
    if !rest.is_empty() {
        out.extend_from_slice(&UpstreamBase62::decode(rest));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn keeps_encoding_for_non_leading_zero_input() {
        let input = [0x12, 0x34, 0x56];
        assert_eq!(encode(&input), codeckit::Base62::encode(&input));
    }

    #[test]
    fn rewrites_leading_zero_marker_to_zero_digit() {
        assert_eq!(encode(&[0]), "0");
        assert_eq!(encode(&[0, 0]), "00");
        assert_eq!(encode(&[0, 1]), "01");
        assert_eq!(encode(&[0, 0, 0xff]), "0047");
    }

    #[test]
    fn decode_restores_leading_zero_bytes() {
        assert_eq!(decode("0"), vec![0]);
        assert_eq!(decode("00"), vec![0, 0]);
        assert_eq!(decode("01"), vec![0, 1]);
        assert_eq!(decode("0047"), vec![0, 0, 0xff]);
    }

    #[test]
    fn round_trips_byte_sequences_with_leading_zeroes() {
        for input in [
            vec![0],
            vec![0, 1],
            vec![0, 0, 1],
            vec![0, 0xff],
            vec![0, 0, 0xff],
            vec![0, 0x12, 0x34, 0x56],
        ] {
            assert_eq!(decode(&encode(&input)), input);
        }
    }
}
