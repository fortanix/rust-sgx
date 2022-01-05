use aws_nitro_enclaves_cose::crypto::{Hash, MessageDigest, SignatureAlgorithm, SigningPublicKey};
use aws_nitro_enclaves_cose::error::CoseError;
use mbedtls::alloc::Box as MbedtlsBox;
use mbedtls::hash::{self, Md};
use mbedtls::pk::dsa;
use mbedtls::pk::EcGroupId;
use mbedtls::x509::Certificate;
use std::sync::Mutex;
use std::ops::Deref;

pub(crate) struct Mbedtls;

struct MdType(hash::Type);

impl From<MessageDigest> for MdType {
    fn from(md: MessageDigest) -> MdType {
        match md {
            MessageDigest::Sha256 => MdType(hash::Type::Sha256),
            MessageDigest::Sha384 => MdType(hash::Type::Sha384),
            MessageDigest::Sha512 => MdType(hash::Type::Sha512),
        }
    }
}

impl Deref for MdType {
    type Target = hash::Type;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Hash for Mbedtls {
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        let md = MdType::from(digest);

        let mut output = vec![0u8; 64]; // biggest in SHA-512
        let len =
            Md::hash(*md, data, &mut output).map_err(|e| CoseError::HashingError(Box::new(e)))?;
        output.truncate(len);
        Ok(output)
    }
}

pub(crate) struct WrappedCert(Mutex<MbedtlsBox<Certificate>>);

impl WrappedCert {
    pub(crate) fn new(cert: MbedtlsBox<Certificate>) -> Self {
        WrappedCert(Mutex::new(cert))
    }
}

impl SigningPublicKey for WrappedCert {
    fn get_parameters(&self) -> Result<(SignatureAlgorithm, MessageDigest), CoseError> {
        let pk = self.0.lock().unwrap();
        let pk = pk.public_key();
        let curve_name = pk
            .curve()
            .map_err(|_| CoseError::UnsupportedError("Unsupported key".to_string()))?;
        let curve_parameters = ec_curve_to_parameters(curve_name)?;

        Ok((curve_parameters.0, curve_parameters.1))
    }

    fn verify(&self, digest: &[u8], signature: &[u8]) -> Result<bool, CoseError> {
        let mut pk = self.0.lock().unwrap();
        let pk = pk.public_key_mut();
        let curve_name = pk
            .curve()
            .map_err(|_| CoseError::UnsupportedError("Unsupported key".to_string()))?;
        let (_, mdtype, key_length) = ec_curve_to_parameters(curve_name)?;

        // Recover the R and S factors from the signature contained in the object
        let (bytes_r, bytes_s) = signature.split_at(key_length);

        let sig = dsa::serialize_signature(bytes_r, bytes_s)
            .map_err(|e| CoseError::SignatureError(Box::new(e)))?;

        let md = MdType::from(mdtype);

        // We'll throw error if signature verify does not work
        match pk.verify(*md, &digest, &sig) {
            Ok(_) => Ok(true),
            Err(mbedtls::Error::EcpVerifyFailed) => Ok(false),
            Err(e) => Err(CoseError::SignatureError(Box::new(e))),
        }
    }
}

pub fn ec_curve_to_parameters(
    curve_name: EcGroupId,
) -> Result<(SignatureAlgorithm, MessageDigest, usize), CoseError> {
    let sig_alg = match curve_name {
        // Recommended to use with SHA256
        EcGroupId::SecP256R1 => SignatureAlgorithm::ES256,
        // Recommended to use with SHA384
        EcGroupId::SecP384R1 => SignatureAlgorithm::ES384,
        // Recommended to use with SHA512
        EcGroupId::SecP521R1 => SignatureAlgorithm::ES512,
        _ => {
            return Err(CoseError::UnsupportedError(format!(
                "Curve name {:?} is not supported",
                curve_name
            )))
        }
    };

    Ok((
        sig_alg,
        sig_alg.suggested_message_digest(),
        sig_alg.key_length(),
    ))
}
