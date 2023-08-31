use chrono::NaiveDate;
use crypto_bigint::U2048;
use lazy_static::lazy_static;
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct KeyId {
    pub rid: [u8; 5],
    pub index: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub struct KeyData {
    pub expiry: NaiveDate,
    pub exponent: u32,
    pub modulus: U2048,
}

macro_rules! keys_map {
    [$($rid:literal, $index:expr => $year:literal-$month:literal-$day:literal, $exponent:expr, $modulus:literal,)*] => {
        HashMap::from([$(
            (
                KeyId {
                    rid: hex::decode($rid).unwrap().try_into().unwrap(),
                    index: $index
                },
                KeyData {
                    expiry: NaiveDate::from_ymd_opt($year, $month, $day).unwrap(),
                    exponent: $exponent,
                    modulus: U2048::from_be_hex(&format!("{:0>512}", $modulus.replace(" ", "")))
                }
            )
        ,)*])
    };
}
lazy_static! {
    pub static ref CA_KEYS: HashMap<KeyId, KeyData> = keys_map![
        "A000000004", 0x05 => 2024-12-31, 3, "B8 04 8A BC 30 C9 0D 97 63 36 54 3E 3F D7 09 1C 8F E4 80 0D F8 20 ED 55 E7 E9 48 13 ED 00 55 5B 57 3F EC A3 D8 4A F6 13 1A 65 1D 66 CF F4 28 4F B1 3B 63 5E DD 0E E4 01 76 D8 BF 04 B7 FD 1C 7B AC F9 AC 73 27 DF AA 8A A7 2D 10 DB 3B 8E 70 B2 DD D8 11 CB 41 96 52 5E A3 86 AC C3 3C 0D 9D 45 75 91 64 69 C4 E4 F5 3E 8E 1C 91 2C C6 18 CB 22 DD E7 C3 56 8E 90 02 2E 6B BA 77 02 02 E4 52 2A 2D D6 23 D1 80 E2 15 BD 1D 15 07 FE 3D C9 0C A3 10 D2 7B 3E FC CD 8F 83 DE 30 52 CA D1 E4 89 38 C6 8D 09 5A AC 91 B5 F3 7E 28 BB 49 EC 7E D5 97",
        "A000000004", 0x06 => 2028-12-31, 3, "CB 26 FC 83 0B 43 78 5B 2B CE 37 C8 1E D3 34 62 2F 96 22 F4 C8 9A AE 64 10 46 B2 35 34 33 88 3F 30 7F B7 C9 74 16 2D A7 2F 7A 4E C7 5D 9D 65 73 36 86 5B 8D 30 23 D3 D6 45 66 76 25 C9 A0 7A 6B 7A 13 7C F0 C6 41 98 AE 38 FC 23 80 06 FB 26 03 F4 1F 4F 3B B9 DA 13 47 27 0F 2F 5D 8C 60 6E 42 09 58 C5 F7 D5 0A 71 DE 30 14 2F 70 DE 46 88 89 B5 E3 A0 86 95 B9 38 A5 0F C9 80 39 3A 9C BC E4 4A D2 D6 4F 63 0B B3 3A D3 F5 F5 FD 49 5D 31 F3 78 18 C1 D9 40 71 34 2E 07 F1 BE C2 19 4F 60 35 BA 5D ED 39 36 50 0E B8 2D FD A6 E8 AF B6 55 B1 EF 3D 0D 7E BF 86 B6 6D D9 F2 9F 6B 1D 32 4F E8 B2 6C E3 8A B2 01 3D D1 3F 61 1E 7A 59 4D 67 5C 44 32 35 0E A2 44 CC 34 F3 87 3C BA 06 59 29 87 A1 D7 E8 52 AD C2 2E F5 A2 EE 28 13 20 31 E4 8F 74 03 7E 3B 34 AB 74 7F",
        "A000000152", 0x05 => 2028-12-31, 3, "E1 20 0E 9F 44 28 EB 71 A5 26 D6 BB 44 C9 57 F1 8F 27 B2 0B AC E9 78 06 1C CE F2 35 32 DB EB FA F6 54 A1 49 70 1C 14 E6 A2 A7 C2 EC AC 4C 92 13 5B E3 E9 25 83 31 DD B0 96 7C 3D 1D 37 5B 99 6F 25 B7 78 11 CC CC 06 A1 53 B4 CE 69 90 A5 1A 02 58 EA 84 37 ED BE B7 01 CB 1F 33 59 93 E3 F4 84 58 BC 11 94 BA D2 9B F6 83 D5 F3 EC B9 84 E3 1B 7B 9D 2F 6D 94 7B 39 DE DE 02 79 EE 45 B4 7F 2F 3D 4E EE F9 3F 92 61 F8 F5 A5 71 AF BF B5 69 C1 50 37 0A 78 F6 68 3D 68 7C B6 77 77 7B 2E 7A BE FC FC 8F 5F 93 50 17 36 99 7E 83 10 EE 0F D8 7A FA C5 DA 77 2B A2 77 F8 8B 44 45 9F CA 56 35 55 01 7C D0 D6 67 71 43 7F 8B 66 08 AA 1A 66 5F 88 D8 46 40 3E 4C 41 AF EE DB 97 29 C2 B2 51 1C FE 22 8B 50 C1 B1 52 B2 A6 0B BF 61 D8 91 3E 08 62 10 02 3A 3A A4 99 E4 23",
    ];
}
