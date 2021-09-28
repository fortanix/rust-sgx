use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand;

const MANAGER_RSA_KEY_SIZE: u32 = 3072;
const MANAGER_RSA_KEY_EXP: u32 = 0x10001;

fn main() {
    let key = Pk::generate_rsa(&mut Rdrand, MANAGER_RSA_KEY_SIZE, MANAGER_RSA_KEY_EXP).unwrap();
    assert_eq!(MANAGER_RSA_KEY_EXP, key.rsa_public_exponent().unwrap());
}
