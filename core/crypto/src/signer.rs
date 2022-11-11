use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::key_conversion::convert_secret_key;
use crate::key_file::KeyFile;
use crate::{KeyType, PublicKey, SecretKey, Signature};
use near_account_id::AccountId;

use serde::{Deserialize, Serialize};

/// Generic signer trait, that can sign with some subset of supported curves.
pub trait Signer: Sync + Send {
    fn public_key(&self) -> PublicKey;
    fn sign(&self, data: &[u8]) -> Signature;

    fn verify(&self, data: &[u8], signature: &Signature) -> bool {
        signature.verify(data, &self.public_key())
    }

    fn compute_vrf_with_proof(&self, _data: &[u8]) -> (crate::vrf::Value, crate::vrf::Proof);

    /// Used by test infrastructure, only implement if make sense for testing otherwise raise `unimplemented`.
    fn write_to_file(&self, _path: &Path) -> io::Result<()> {
        unimplemented!();
    }
}

// Signer that returns empty signature. Used for transaction testing.
pub struct EmptySigner {}

impl Signer for EmptySigner {
    fn public_key(&self) -> PublicKey {
        PublicKey::empty(KeyType::ED25519)
    }

    fn sign(&self, _data: &[u8]) -> Signature {
        Signature::empty(KeyType::ED25519)
    }

    fn compute_vrf_with_proof(&self, _data: &[u8]) -> (crate::vrf::Value, crate::vrf::Proof) {
        unimplemented!()
    }
}

/// Signer that keeps secret key in memory.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct InMemorySigner {
    pub account_id: AccountId,
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

impl InMemorySigner {
    pub fn from_seed(account_id: AccountId, key_type: KeyType, seed: &str) -> Self {
        let secret_key = SecretKey::from_seed(key_type, seed);
        Self { account_id, public_key: secret_key.public_key(), secret_key }
    }

    pub fn from_secret_key(account_id: AccountId, secret_key: SecretKey) -> Self {
        Self { account_id, public_key: secret_key.public_key(), secret_key }
    }

    pub fn from_file(path: &Path) -> io::Result<Self> {
        KeyFile::from_file(path).map(Self::from)
    }
}

impl Signer for InMemorySigner {
    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }

    fn sign(&self, data: &[u8]) -> Signature {
        self.secret_key.sign(data)
    }

    fn compute_vrf_with_proof(&self, data: &[u8]) -> (crate::vrf::Value, crate::vrf::Proof) {
        let secret_key = convert_secret_key(self.secret_key.unwrap_as_ed25519());
        secret_key.compute_vrf_with_proof(&data)
    }

    fn write_to_file(&self, path: &Path) -> io::Result<()> {
        KeyFile::from(self).write_to_file(path)
    }
}

impl From<KeyFile> for InMemorySigner {
    fn from(key_file: KeyFile) -> Self {
        Self {
            account_id: key_file.account_id,
            public_key: key_file.public_key,
            secret_key: key_file.secret_key,
        }
    }
}

impl From<&InMemorySigner> for KeyFile {
    fn from(signer: &InMemorySigner) -> KeyFile {
        KeyFile {
            account_id: signer.account_id.clone(),
            public_key: signer.public_key.clone(),
            secret_key: signer.secret_key.clone(),
        }
    }
}

impl From<Arc<InMemorySigner>> for KeyFile {
    fn from(signer: Arc<InMemorySigner>) -> KeyFile {
        KeyFile {
            account_id: signer.account_id.clone(),
            public_key: signer.public_key.clone(),
            secret_key: signer.secret_key.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use serde_json::{from_str, to_string};
    use std::str::FromStr;
    use std::io::Write;

    #[test]
    fn test_in_memory_signer() {
        fn load(contents: &[u8]) -> io::Result<InMemorySigner> {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.as_file().write_all(contents).unwrap();
            let result = InMemorySigner::from_file(tmp.path());
            tmp.close().unwrap();
            result
        }

        // Testing from seed
        let account_id = AccountId::from_str("test").unwrap();
        dbg!(&account_id);
        let signer = InMemorySigner::from_seed(account_id, KeyType::ED25519, "test");
        assert_eq!(signer.public_key, PublicKey::from_str("DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847").unwrap());
        assert_eq!(signer.secret_key, SecretKey::from_str("3KyUuch8pYP47krBq4DosFEVBMR5wDTMQ8AThzM8kAEcBQEpsPdYTZ2FPX5ZnSoLrerjwg66hwwJaW1wHzprd5k3").unwrap());
        assert_eq!(signer.account_id, AccountId::from_str("test").unwrap());
        
        // Testing from secret key
        let secret_key = SecretKey::from_str("3KyUuch8pYP47krBq4DosFEVBMR5wDTMQ8AThzM8kAEcBQEpsPdYTZ2FPX5ZnSoLrerjwg66hwwJaW1wHzprd5k3").unwrap();
        let account_id = AccountId::from_str("test").unwrap();
        let signer = InMemorySigner::from_secret_key(account_id, secret_key);
        assert_eq!(signer.public_key, PublicKey::from_str("DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847").unwrap());
        assert_eq!(signer.secret_key, SecretKey::from_str("3KyUuch8pYP47krBq4DosFEVBMR5wDTMQ8AThzM8kAEcBQEpsPdYTZ2FPX5ZnSoLrerjwg66hwwJaW1wHzprd5k3").unwrap());
        assert_eq!(signer.account_id, AccountId::from_str("test").unwrap());

        //Testing from file
        let signer = load(br#"{
            "account_id": "test",
            "public_key": "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847",
            "secret_key": "ed25519:3KyUuch8pYP47krBq4DosFEVBMR5wDTMQ8AThzM8kAEcBQEpsPdYTZ2FPX5ZnSoLrerjwg66hwwJaW1wHzprd5k3"
        }"#).unwrap();
        assert_eq!(signer.public_key, PublicKey::from_str("DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847").unwrap());
        assert_eq!(signer.secret_key, SecretKey::from_str("3KyUuch8pYP47krBq4DosFEVBMR5wDTMQ8AThzM8kAEcBQEpsPdYTZ2FPX5ZnSoLrerjwg66hwwJaW1wHzprd5k3").unwrap());
        assert_eq!(signer.account_id, AccountId::from_str("test").unwrap());
    }
}
