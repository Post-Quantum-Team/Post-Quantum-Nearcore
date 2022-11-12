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
    use std::str::FromStr;
    use std::io::Write;

    #[test]
    fn test_in_memory_signer_ed25519() {
        fn load(contents: &[u8]) -> io::Result<InMemorySigner> {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.as_file().write_all(contents).unwrap();
            let result = InMemorySigner::from_file(tmp.path());
            tmp.close().unwrap();
            result
        }

        // Testing from seed
        let account_id = AccountId::from_str("test").unwrap();
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

    #[test]
    fn test_in_memory_signer_falcon512() {
        fn load(contents: &[u8]) -> io::Result<InMemorySigner> {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.as_file().write_all(contents).unwrap();
            let result = InMemorySigner::from_file(tmp.path());
            tmp.close().unwrap();
            result
        }

        // Testing from seed
        let account_id = AccountId::from_str("test").unwrap();
        let signer = InMemorySigner::from_seed(account_id, KeyType::FALCON512, "test");
        assert_eq!(signer.public_key, PublicKey::from_str("falcon512:3AATidp6iTx4krz2WAgNzeSYRFJHyoiemAnLuaFNJeZePRrKT5LiHPPLh2y3f3E1hMmrQ6NNfJ9o9k1UwPDi3ha7TNvNStwER3fiw8tzAWT1CQqJizGUyr63Pdr175KjpwJwe5esnSuWHHBUABLYPuta7KDqr8dQB3BFBQYN5TzEUZFCkDmGuSQBmpVVw8qx3eKzKbgPhqzNxAwTSFFPBeeqCSxCRCzNUpSckqYTyAbsMbf325vEh5g8k9sX1eHG2HkZxhJvecXb68AJ55QC6vuePt5MGnkzq8DWuvrN2tCskQdXwtnG8yLJqme6muCwL2qCDXCY1bqWVwcs3ASTsENdtMazGobkrdGexdE2LRVyKHDjYuG6voJHKhaYN2SnV1XBb8d6pN3f3cMN6Z8y1R6gBPpKayh8je3D1tUBEt64YmPAXy7t8XF6hdqJMXmbTk7gRZqcakpj1EUBtpSzH8mjHNxXaGsj12s14yxgutcNMgwsp3DHBzM48Z2if8s4mAgQZnxAJWabrTyD6v2mjeRQ21qMtqY9osmvuaTcLsNkK7bEWXLqUfmWzskTLo5p24LLzuq31yH4b4VqMeb9Rpy5YjHiJYvMFW2NdiazsQsLE9zgfCh9bJDjAc5PoeMJrLbgybEJqcosT6pQ4qcHGgzVQqtdS6RtWrReoc71MrfdD4SUsHM9FSvV3bwEQ3k9GRdjw3Vhs63rRzyri89RJYV7nLjDoWR3VS5WW2D2hPfmwS2DdPURzD3U196b23iicq5oXtMsYvpfU6V4UJccwBni2UZtaHGGnAbPjmbV6b8QtHs3d5jo3684raGCJQb5Pyi6qZEuwgPLXUKUzNcWYeK9qXQxcL9gqCb6UJQfdHJpRddMSLTrVepqJEjExgETZcBPARxVzbRJ3KxQ9MuZUgJt4DjEu74FoNSZmG4NjdekGuNSiqQ47pHKji8VfXbPGCBQf2Rfui5ZbseRDFqsrMNkZAWFJZfnteiisYjD5kdsbffAPVntAT4Pwu3dFrcdMxRJUf4wkPjHmrru5spSMfjKXRdcGmNDdNurmopkR3mQoPEfYiYJ2Sy99Z7sESaG1mpMiL65gqRj1XKUcJTKzUeaMZv5V3b4JLFkWcxwS5iAQecY7Z14xWexEkX4rujmQKLvaVsFcAvFjmhaKCpsbMuTjc1TSZYg8HvqaHgnZyaRZ8rZJqX7PKPAD1cDwtgH813ptgApj").unwrap());
        assert_eq!(signer.secret_key, SecretKey::from_str("falcon512:2qxHMdQoES3ZkuFrmVCuSQ4nU5BjafSKxR7xNpLUi2NVFpErkq6b7jTYUJ4uP9wbvDL1edSPCmMjtXE844RGQRTCvWr4doW8gFtiJw7wLtDzzZgsGDyj9sR7nWmbdw5b7H5s8uRozDGeJr3FKtghUsF5HZsLdXyhmz2K4gH5a3waP1bdwAtfWGukkCbrstpagGtPYgoDpw6auCMoNKN6pCV4MQVz6gmqCGCB324w3phZmyHMrgpoWQKBrnfVtZADRDP96EuffS1NXJCzzvd3htU8KdCjPrTs51VNvss7XenWpnhDPSLCT1KaP4oRtoJr5US15g9bjdiT6zCbDfvvW7J94BF2CXDCUjkaoonkqLQei642iRi6ZovcceYJoN3qvTGk8P6vWFxbW9ffyM2pw1Gfs79xbyAVKHVaxWs4TxGN7XcYf6NyQYPRuoaMQiLAtdq2jayvQEHwttFPHdfXwGejCtAxMRZtwxzkoiaXMctGSdSfZNYgWib7cHsyaUW8SVBq3sVYo6NxTK579FxdNdpJ3BD3mVx5NpfxaatteYZmBeYeWpUwz22rDakehsW3ByMjUVgnLiHpMadEXPVAMeGMyTrKUzH4fxJCDAHQYunsCAGuMPjmzFpYj65WxgVrMDjvgL97ZZELzebA1svMgVYnRyPZLDvwKm6HMzFrRV4GLie4Tb14N61Q7oCPfcHmt5nQT1NpiwzMMDm3WMp6ntM7P39m6quToiwjuEn51odgXgtfSxuPGVhvsZqtKjJkEKiGQsML1vj4MHkdBWbYedgDorftSw4qXbdoYu7Nkwi68QUhF97RZpbJT35awnnjARzHrivM7A9v8pMShFEEBB1ScNbrQ7XcZ3ZimWzPNYuP4gZji5YzMoo74ZJW77yX58fmhtZauSLX4KsYaVzrEQWUue1bKwJTawFZ3UwXFFM3K3Mvnxh9Jxsnkt8igpDHuk5bzy8UmBhySNQffYNjVc5942hmf4Sx69JfTxtmWR48XzwGYfs8PwxgjS6f9oFjutzUhzGixDfCuoQ1WuTvYoYSkU3cNQuMpBit4E6XvrYBDhgrxekZJZ7aDqf9VKwdbUcAPmfQkK2hyJMXzq57Mw2dogq1DvBj8B4CA68pWoVrkTRfPxJ2jP4G7PNF1cjKTLtB4reAHi99ReEGk9dRxXfK89muTE8u9GW6qzpuAn1ohjUbVyqYozTBDgsTGRLR4KLWKiSREvimazxcrAkg2A1bM4mwZrz6Q1e4ySdb59PBAHEBjjRpDgJ7u4TWXzaAaBrm5fJWz8dgeoCCCvKNGrHvd8zjDLANrQgKMwzeWsXpotR6rimSJZNFb75HG3WoicPs8AzYpdgqVJm8m94VJK4G45XACZgRTbdMvDdAJXVKpZC2NJ9oDuPabiRrYMx9TfGKqA2tP9tQGyDNCqcDpgirFwCgWU81964oJr4FyghxYYhPwBRmABfKB8NJ64od4TyAJRrTA25E1HJmr5U5dyJ4QAtxHobU8kyMwqEmQTmpL9zDVfV1ZikvkVXgYrbwFEf6kLLmSU9c7tNaR8NHWdDCuNcHvnYb4cweuWq3t6oaPqumusmoAJxrekNHXYPNzwJ5eFjyKJz783PTGAJQUy1qy1tbCNog61rjvmGCrr1Ld2ejwgXxkAGQjBnBwXJzULPoH6vz6StKNZe2kgi58WQhENaoN3UV12dSzVmCFQAxbK4R4km71UTDhwb8ryYivwTLTQSWMhBwkLsY94QGFk").unwrap());
        assert_eq!(signer.account_id, AccountId::from_str("test").unwrap());
        
        // Testing from secret key
        let secret_key = SecretKey::from_str("falcon512:2qxHMdQoES3ZkuFrmVCuSQ4nU5BjafSKxR7xNpLUi2NVFpErkq6b7jTYUJ4uP9wbvDL1edSPCmMjtXE844RGQRTCvWr4doW8gFtiJw7wLtDzzZgsGDyj9sR7nWmbdw5b7H5s8uRozDGeJr3FKtghUsF5HZsLdXyhmz2K4gH5a3waP1bdwAtfWGukkCbrstpagGtPYgoDpw6auCMoNKN6pCV4MQVz6gmqCGCB324w3phZmyHMrgpoWQKBrnfVtZADRDP96EuffS1NXJCzzvd3htU8KdCjPrTs51VNvss7XenWpnhDPSLCT1KaP4oRtoJr5US15g9bjdiT6zCbDfvvW7J94BF2CXDCUjkaoonkqLQei642iRi6ZovcceYJoN3qvTGk8P6vWFxbW9ffyM2pw1Gfs79xbyAVKHVaxWs4TxGN7XcYf6NyQYPRuoaMQiLAtdq2jayvQEHwttFPHdfXwGejCtAxMRZtwxzkoiaXMctGSdSfZNYgWib7cHsyaUW8SVBq3sVYo6NxTK579FxdNdpJ3BD3mVx5NpfxaatteYZmBeYeWpUwz22rDakehsW3ByMjUVgnLiHpMadEXPVAMeGMyTrKUzH4fxJCDAHQYunsCAGuMPjmzFpYj65WxgVrMDjvgL97ZZELzebA1svMgVYnRyPZLDvwKm6HMzFrRV4GLie4Tb14N61Q7oCPfcHmt5nQT1NpiwzMMDm3WMp6ntM7P39m6quToiwjuEn51odgXgtfSxuPGVhvsZqtKjJkEKiGQsML1vj4MHkdBWbYedgDorftSw4qXbdoYu7Nkwi68QUhF97RZpbJT35awnnjARzHrivM7A9v8pMShFEEBB1ScNbrQ7XcZ3ZimWzPNYuP4gZji5YzMoo74ZJW77yX58fmhtZauSLX4KsYaVzrEQWUue1bKwJTawFZ3UwXFFM3K3Mvnxh9Jxsnkt8igpDHuk5bzy8UmBhySNQffYNjVc5942hmf4Sx69JfTxtmWR48XzwGYfs8PwxgjS6f9oFjutzUhzGixDfCuoQ1WuTvYoYSkU3cNQuMpBit4E6XvrYBDhgrxekZJZ7aDqf9VKwdbUcAPmfQkK2hyJMXzq57Mw2dogq1DvBj8B4CA68pWoVrkTRfPxJ2jP4G7PNF1cjKTLtB4reAHi99ReEGk9dRxXfK89muTE8u9GW6qzpuAn1ohjUbVyqYozTBDgsTGRLR4KLWKiSREvimazxcrAkg2A1bM4mwZrz6Q1e4ySdb59PBAHEBjjRpDgJ7u4TWXzaAaBrm5fJWz8dgeoCCCvKNGrHvd8zjDLANrQgKMwzeWsXpotR6rimSJZNFb75HG3WoicPs8AzYpdgqVJm8m94VJK4G45XACZgRTbdMvDdAJXVKpZC2NJ9oDuPabiRrYMx9TfGKqA2tP9tQGyDNCqcDpgirFwCgWU81964oJr4FyghxYYhPwBRmABfKB8NJ64od4TyAJRrTA25E1HJmr5U5dyJ4QAtxHobU8kyMwqEmQTmpL9zDVfV1ZikvkVXgYrbwFEf6kLLmSU9c7tNaR8NHWdDCuNcHvnYb4cweuWq3t6oaPqumusmoAJxrekNHXYPNzwJ5eFjyKJz783PTGAJQUy1qy1tbCNog61rjvmGCrr1Ld2ejwgXxkAGQjBnBwXJzULPoH6vz6StKNZe2kgi58WQhENaoN3UV12dSzVmCFQAxbK4R4km71UTDhwb8ryYivwTLTQSWMhBwkLsY94QGFk").unwrap();
        let account_id = AccountId::from_str("test").unwrap();
        let signer = InMemorySigner::from_secret_key(account_id, secret_key);
        assert_eq!(signer.public_key, PublicKey::from_str("falcon512:3AATidp6iTx4krz2WAgNzeSYRFJHyoiemAnLuaFNJeZePRrKT5LiHPPLh2y3f3E1hMmrQ6NNfJ9o9k1UwPDi3ha7TNvNStwER3fiw8tzAWT1CQqJizGUyr63Pdr175KjpwJwe5esnSuWHHBUABLYPuta7KDqr8dQB3BFBQYN5TzEUZFCkDmGuSQBmpVVw8qx3eKzKbgPhqzNxAwTSFFPBeeqCSxCRCzNUpSckqYTyAbsMbf325vEh5g8k9sX1eHG2HkZxhJvecXb68AJ55QC6vuePt5MGnkzq8DWuvrN2tCskQdXwtnG8yLJqme6muCwL2qCDXCY1bqWVwcs3ASTsENdtMazGobkrdGexdE2LRVyKHDjYuG6voJHKhaYN2SnV1XBb8d6pN3f3cMN6Z8y1R6gBPpKayh8je3D1tUBEt64YmPAXy7t8XF6hdqJMXmbTk7gRZqcakpj1EUBtpSzH8mjHNxXaGsj12s14yxgutcNMgwsp3DHBzM48Z2if8s4mAgQZnxAJWabrTyD6v2mjeRQ21qMtqY9osmvuaTcLsNkK7bEWXLqUfmWzskTLo5p24LLzuq31yH4b4VqMeb9Rpy5YjHiJYvMFW2NdiazsQsLE9zgfCh9bJDjAc5PoeMJrLbgybEJqcosT6pQ4qcHGgzVQqtdS6RtWrReoc71MrfdD4SUsHM9FSvV3bwEQ3k9GRdjw3Vhs63rRzyri89RJYV7nLjDoWR3VS5WW2D2hPfmwS2DdPURzD3U196b23iicq5oXtMsYvpfU6V4UJccwBni2UZtaHGGnAbPjmbV6b8QtHs3d5jo3684raGCJQb5Pyi6qZEuwgPLXUKUzNcWYeK9qXQxcL9gqCb6UJQfdHJpRddMSLTrVepqJEjExgETZcBPARxVzbRJ3KxQ9MuZUgJt4DjEu74FoNSZmG4NjdekGuNSiqQ47pHKji8VfXbPGCBQf2Rfui5ZbseRDFqsrMNkZAWFJZfnteiisYjD5kdsbffAPVntAT4Pwu3dFrcdMxRJUf4wkPjHmrru5spSMfjKXRdcGmNDdNurmopkR3mQoPEfYiYJ2Sy99Z7sESaG1mpMiL65gqRj1XKUcJTKzUeaMZv5V3b4JLFkWcxwS5iAQecY7Z14xWexEkX4rujmQKLvaVsFcAvFjmhaKCpsbMuTjc1TSZYg8HvqaHgnZyaRZ8rZJqX7PKPAD1cDwtgH813ptgApj").unwrap());
        assert_eq!(signer.secret_key, SecretKey::from_str("falcon512:2qxHMdQoES3ZkuFrmVCuSQ4nU5BjafSKxR7xNpLUi2NVFpErkq6b7jTYUJ4uP9wbvDL1edSPCmMjtXE844RGQRTCvWr4doW8gFtiJw7wLtDzzZgsGDyj9sR7nWmbdw5b7H5s8uRozDGeJr3FKtghUsF5HZsLdXyhmz2K4gH5a3waP1bdwAtfWGukkCbrstpagGtPYgoDpw6auCMoNKN6pCV4MQVz6gmqCGCB324w3phZmyHMrgpoWQKBrnfVtZADRDP96EuffS1NXJCzzvd3htU8KdCjPrTs51VNvss7XenWpnhDPSLCT1KaP4oRtoJr5US15g9bjdiT6zCbDfvvW7J94BF2CXDCUjkaoonkqLQei642iRi6ZovcceYJoN3qvTGk8P6vWFxbW9ffyM2pw1Gfs79xbyAVKHVaxWs4TxGN7XcYf6NyQYPRuoaMQiLAtdq2jayvQEHwttFPHdfXwGejCtAxMRZtwxzkoiaXMctGSdSfZNYgWib7cHsyaUW8SVBq3sVYo6NxTK579FxdNdpJ3BD3mVx5NpfxaatteYZmBeYeWpUwz22rDakehsW3ByMjUVgnLiHpMadEXPVAMeGMyTrKUzH4fxJCDAHQYunsCAGuMPjmzFpYj65WxgVrMDjvgL97ZZELzebA1svMgVYnRyPZLDvwKm6HMzFrRV4GLie4Tb14N61Q7oCPfcHmt5nQT1NpiwzMMDm3WMp6ntM7P39m6quToiwjuEn51odgXgtfSxuPGVhvsZqtKjJkEKiGQsML1vj4MHkdBWbYedgDorftSw4qXbdoYu7Nkwi68QUhF97RZpbJT35awnnjARzHrivM7A9v8pMShFEEBB1ScNbrQ7XcZ3ZimWzPNYuP4gZji5YzMoo74ZJW77yX58fmhtZauSLX4KsYaVzrEQWUue1bKwJTawFZ3UwXFFM3K3Mvnxh9Jxsnkt8igpDHuk5bzy8UmBhySNQffYNjVc5942hmf4Sx69JfTxtmWR48XzwGYfs8PwxgjS6f9oFjutzUhzGixDfCuoQ1WuTvYoYSkU3cNQuMpBit4E6XvrYBDhgrxekZJZ7aDqf9VKwdbUcAPmfQkK2hyJMXzq57Mw2dogq1DvBj8B4CA68pWoVrkTRfPxJ2jP4G7PNF1cjKTLtB4reAHi99ReEGk9dRxXfK89muTE8u9GW6qzpuAn1ohjUbVyqYozTBDgsTGRLR4KLWKiSREvimazxcrAkg2A1bM4mwZrz6Q1e4ySdb59PBAHEBjjRpDgJ7u4TWXzaAaBrm5fJWz8dgeoCCCvKNGrHvd8zjDLANrQgKMwzeWsXpotR6rimSJZNFb75HG3WoicPs8AzYpdgqVJm8m94VJK4G45XACZgRTbdMvDdAJXVKpZC2NJ9oDuPabiRrYMx9TfGKqA2tP9tQGyDNCqcDpgirFwCgWU81964oJr4FyghxYYhPwBRmABfKB8NJ64od4TyAJRrTA25E1HJmr5U5dyJ4QAtxHobU8kyMwqEmQTmpL9zDVfV1ZikvkVXgYrbwFEf6kLLmSU9c7tNaR8NHWdDCuNcHvnYb4cweuWq3t6oaPqumusmoAJxrekNHXYPNzwJ5eFjyKJz783PTGAJQUy1qy1tbCNog61rjvmGCrr1Ld2ejwgXxkAGQjBnBwXJzULPoH6vz6StKNZe2kgi58WQhENaoN3UV12dSzVmCFQAxbK4R4km71UTDhwb8ryYivwTLTQSWMhBwkLsY94QGFk").unwrap());
        assert_eq!(signer.account_id, AccountId::from_str("test").unwrap());

        //Testing from file
        let signer = load(br#"{
            "account_id": "test",
            "public_key": "falcon512:3AATidp6iTx4krz2WAgNzeSYRFJHyoiemAnLuaFNJeZePRrKT5LiHPPLh2y3f3E1hMmrQ6NNfJ9o9k1UwPDi3ha7TNvNStwER3fiw8tzAWT1CQqJizGUyr63Pdr175KjpwJwe5esnSuWHHBUABLYPuta7KDqr8dQB3BFBQYN5TzEUZFCkDmGuSQBmpVVw8qx3eKzKbgPhqzNxAwTSFFPBeeqCSxCRCzNUpSckqYTyAbsMbf325vEh5g8k9sX1eHG2HkZxhJvecXb68AJ55QC6vuePt5MGnkzq8DWuvrN2tCskQdXwtnG8yLJqme6muCwL2qCDXCY1bqWVwcs3ASTsENdtMazGobkrdGexdE2LRVyKHDjYuG6voJHKhaYN2SnV1XBb8d6pN3f3cMN6Z8y1R6gBPpKayh8je3D1tUBEt64YmPAXy7t8XF6hdqJMXmbTk7gRZqcakpj1EUBtpSzH8mjHNxXaGsj12s14yxgutcNMgwsp3DHBzM48Z2if8s4mAgQZnxAJWabrTyD6v2mjeRQ21qMtqY9osmvuaTcLsNkK7bEWXLqUfmWzskTLo5p24LLzuq31yH4b4VqMeb9Rpy5YjHiJYvMFW2NdiazsQsLE9zgfCh9bJDjAc5PoeMJrLbgybEJqcosT6pQ4qcHGgzVQqtdS6RtWrReoc71MrfdD4SUsHM9FSvV3bwEQ3k9GRdjw3Vhs63rRzyri89RJYV7nLjDoWR3VS5WW2D2hPfmwS2DdPURzD3U196b23iicq5oXtMsYvpfU6V4UJccwBni2UZtaHGGnAbPjmbV6b8QtHs3d5jo3684raGCJQb5Pyi6qZEuwgPLXUKUzNcWYeK9qXQxcL9gqCb6UJQfdHJpRddMSLTrVepqJEjExgETZcBPARxVzbRJ3KxQ9MuZUgJt4DjEu74FoNSZmG4NjdekGuNSiqQ47pHKji8VfXbPGCBQf2Rfui5ZbseRDFqsrMNkZAWFJZfnteiisYjD5kdsbffAPVntAT4Pwu3dFrcdMxRJUf4wkPjHmrru5spSMfjKXRdcGmNDdNurmopkR3mQoPEfYiYJ2Sy99Z7sESaG1mpMiL65gqRj1XKUcJTKzUeaMZv5V3b4JLFkWcxwS5iAQecY7Z14xWexEkX4rujmQKLvaVsFcAvFjmhaKCpsbMuTjc1TSZYg8HvqaHgnZyaRZ8rZJqX7PKPAD1cDwtgH813ptgApj",
            "secret_key": "falcon512:2qxHMdQoES3ZkuFrmVCuSQ4nU5BjafSKxR7xNpLUi2NVFpErkq6b7jTYUJ4uP9wbvDL1edSPCmMjtXE844RGQRTCvWr4doW8gFtiJw7wLtDzzZgsGDyj9sR7nWmbdw5b7H5s8uRozDGeJr3FKtghUsF5HZsLdXyhmz2K4gH5a3waP1bdwAtfWGukkCbrstpagGtPYgoDpw6auCMoNKN6pCV4MQVz6gmqCGCB324w3phZmyHMrgpoWQKBrnfVtZADRDP96EuffS1NXJCzzvd3htU8KdCjPrTs51VNvss7XenWpnhDPSLCT1KaP4oRtoJr5US15g9bjdiT6zCbDfvvW7J94BF2CXDCUjkaoonkqLQei642iRi6ZovcceYJoN3qvTGk8P6vWFxbW9ffyM2pw1Gfs79xbyAVKHVaxWs4TxGN7XcYf6NyQYPRuoaMQiLAtdq2jayvQEHwttFPHdfXwGejCtAxMRZtwxzkoiaXMctGSdSfZNYgWib7cHsyaUW8SVBq3sVYo6NxTK579FxdNdpJ3BD3mVx5NpfxaatteYZmBeYeWpUwz22rDakehsW3ByMjUVgnLiHpMadEXPVAMeGMyTrKUzH4fxJCDAHQYunsCAGuMPjmzFpYj65WxgVrMDjvgL97ZZELzebA1svMgVYnRyPZLDvwKm6HMzFrRV4GLie4Tb14N61Q7oCPfcHmt5nQT1NpiwzMMDm3WMp6ntM7P39m6quToiwjuEn51odgXgtfSxuPGVhvsZqtKjJkEKiGQsML1vj4MHkdBWbYedgDorftSw4qXbdoYu7Nkwi68QUhF97RZpbJT35awnnjARzHrivM7A9v8pMShFEEBB1ScNbrQ7XcZ3ZimWzPNYuP4gZji5YzMoo74ZJW77yX58fmhtZauSLX4KsYaVzrEQWUue1bKwJTawFZ3UwXFFM3K3Mvnxh9Jxsnkt8igpDHuk5bzy8UmBhySNQffYNjVc5942hmf4Sx69JfTxtmWR48XzwGYfs8PwxgjS6f9oFjutzUhzGixDfCuoQ1WuTvYoYSkU3cNQuMpBit4E6XvrYBDhgrxekZJZ7aDqf9VKwdbUcAPmfQkK2hyJMXzq57Mw2dogq1DvBj8B4CA68pWoVrkTRfPxJ2jP4G7PNF1cjKTLtB4reAHi99ReEGk9dRxXfK89muTE8u9GW6qzpuAn1ohjUbVyqYozTBDgsTGRLR4KLWKiSREvimazxcrAkg2A1bM4mwZrz6Q1e4ySdb59PBAHEBjjRpDgJ7u4TWXzaAaBrm5fJWz8dgeoCCCvKNGrHvd8zjDLANrQgKMwzeWsXpotR6rimSJZNFb75HG3WoicPs8AzYpdgqVJm8m94VJK4G45XACZgRTbdMvDdAJXVKpZC2NJ9oDuPabiRrYMx9TfGKqA2tP9tQGyDNCqcDpgirFwCgWU81964oJr4FyghxYYhPwBRmABfKB8NJ64od4TyAJRrTA25E1HJmr5U5dyJ4QAtxHobU8kyMwqEmQTmpL9zDVfV1ZikvkVXgYrbwFEf6kLLmSU9c7tNaR8NHWdDCuNcHvnYb4cweuWq3t6oaPqumusmoAJxrekNHXYPNzwJ5eFjyKJz783PTGAJQUy1qy1tbCNog61rjvmGCrr1Ld2ejwgXxkAGQjBnBwXJzULPoH6vz6StKNZe2kgi58WQhENaoN3UV12dSzVmCFQAxbK4R4km71UTDhwb8ryYivwTLTQSWMhBwkLsY94QGFk"
        }"#).unwrap();
        assert_eq!(signer.public_key, PublicKey::from_str("falcon512:3AATidp6iTx4krz2WAgNzeSYRFJHyoiemAnLuaFNJeZePRrKT5LiHPPLh2y3f3E1hMmrQ6NNfJ9o9k1UwPDi3ha7TNvNStwER3fiw8tzAWT1CQqJizGUyr63Pdr175KjpwJwe5esnSuWHHBUABLYPuta7KDqr8dQB3BFBQYN5TzEUZFCkDmGuSQBmpVVw8qx3eKzKbgPhqzNxAwTSFFPBeeqCSxCRCzNUpSckqYTyAbsMbf325vEh5g8k9sX1eHG2HkZxhJvecXb68AJ55QC6vuePt5MGnkzq8DWuvrN2tCskQdXwtnG8yLJqme6muCwL2qCDXCY1bqWVwcs3ASTsENdtMazGobkrdGexdE2LRVyKHDjYuG6voJHKhaYN2SnV1XBb8d6pN3f3cMN6Z8y1R6gBPpKayh8je3D1tUBEt64YmPAXy7t8XF6hdqJMXmbTk7gRZqcakpj1EUBtpSzH8mjHNxXaGsj12s14yxgutcNMgwsp3DHBzM48Z2if8s4mAgQZnxAJWabrTyD6v2mjeRQ21qMtqY9osmvuaTcLsNkK7bEWXLqUfmWzskTLo5p24LLzuq31yH4b4VqMeb9Rpy5YjHiJYvMFW2NdiazsQsLE9zgfCh9bJDjAc5PoeMJrLbgybEJqcosT6pQ4qcHGgzVQqtdS6RtWrReoc71MrfdD4SUsHM9FSvV3bwEQ3k9GRdjw3Vhs63rRzyri89RJYV7nLjDoWR3VS5WW2D2hPfmwS2DdPURzD3U196b23iicq5oXtMsYvpfU6V4UJccwBni2UZtaHGGnAbPjmbV6b8QtHs3d5jo3684raGCJQb5Pyi6qZEuwgPLXUKUzNcWYeK9qXQxcL9gqCb6UJQfdHJpRddMSLTrVepqJEjExgETZcBPARxVzbRJ3KxQ9MuZUgJt4DjEu74FoNSZmG4NjdekGuNSiqQ47pHKji8VfXbPGCBQf2Rfui5ZbseRDFqsrMNkZAWFJZfnteiisYjD5kdsbffAPVntAT4Pwu3dFrcdMxRJUf4wkPjHmrru5spSMfjKXRdcGmNDdNurmopkR3mQoPEfYiYJ2Sy99Z7sESaG1mpMiL65gqRj1XKUcJTKzUeaMZv5V3b4JLFkWcxwS5iAQecY7Z14xWexEkX4rujmQKLvaVsFcAvFjmhaKCpsbMuTjc1TSZYg8HvqaHgnZyaRZ8rZJqX7PKPAD1cDwtgH813ptgApj").unwrap());
        assert_eq!(signer.secret_key, SecretKey::from_str("falcon512:2qxHMdQoES3ZkuFrmVCuSQ4nU5BjafSKxR7xNpLUi2NVFpErkq6b7jTYUJ4uP9wbvDL1edSPCmMjtXE844RGQRTCvWr4doW8gFtiJw7wLtDzzZgsGDyj9sR7nWmbdw5b7H5s8uRozDGeJr3FKtghUsF5HZsLdXyhmz2K4gH5a3waP1bdwAtfWGukkCbrstpagGtPYgoDpw6auCMoNKN6pCV4MQVz6gmqCGCB324w3phZmyHMrgpoWQKBrnfVtZADRDP96EuffS1NXJCzzvd3htU8KdCjPrTs51VNvss7XenWpnhDPSLCT1KaP4oRtoJr5US15g9bjdiT6zCbDfvvW7J94BF2CXDCUjkaoonkqLQei642iRi6ZovcceYJoN3qvTGk8P6vWFxbW9ffyM2pw1Gfs79xbyAVKHVaxWs4TxGN7XcYf6NyQYPRuoaMQiLAtdq2jayvQEHwttFPHdfXwGejCtAxMRZtwxzkoiaXMctGSdSfZNYgWib7cHsyaUW8SVBq3sVYo6NxTK579FxdNdpJ3BD3mVx5NpfxaatteYZmBeYeWpUwz22rDakehsW3ByMjUVgnLiHpMadEXPVAMeGMyTrKUzH4fxJCDAHQYunsCAGuMPjmzFpYj65WxgVrMDjvgL97ZZELzebA1svMgVYnRyPZLDvwKm6HMzFrRV4GLie4Tb14N61Q7oCPfcHmt5nQT1NpiwzMMDm3WMp6ntM7P39m6quToiwjuEn51odgXgtfSxuPGVhvsZqtKjJkEKiGQsML1vj4MHkdBWbYedgDorftSw4qXbdoYu7Nkwi68QUhF97RZpbJT35awnnjARzHrivM7A9v8pMShFEEBB1ScNbrQ7XcZ3ZimWzPNYuP4gZji5YzMoo74ZJW77yX58fmhtZauSLX4KsYaVzrEQWUue1bKwJTawFZ3UwXFFM3K3Mvnxh9Jxsnkt8igpDHuk5bzy8UmBhySNQffYNjVc5942hmf4Sx69JfTxtmWR48XzwGYfs8PwxgjS6f9oFjutzUhzGixDfCuoQ1WuTvYoYSkU3cNQuMpBit4E6XvrYBDhgrxekZJZ7aDqf9VKwdbUcAPmfQkK2hyJMXzq57Mw2dogq1DvBj8B4CA68pWoVrkTRfPxJ2jP4G7PNF1cjKTLtB4reAHi99ReEGk9dRxXfK89muTE8u9GW6qzpuAn1ohjUbVyqYozTBDgsTGRLR4KLWKiSREvimazxcrAkg2A1bM4mwZrz6Q1e4ySdb59PBAHEBjjRpDgJ7u4TWXzaAaBrm5fJWz8dgeoCCCvKNGrHvd8zjDLANrQgKMwzeWsXpotR6rimSJZNFb75HG3WoicPs8AzYpdgqVJm8m94VJK4G45XACZgRTbdMvDdAJXVKpZC2NJ9oDuPabiRrYMx9TfGKqA2tP9tQGyDNCqcDpgirFwCgWU81964oJr4FyghxYYhPwBRmABfKB8NJ64od4TyAJRrTA25E1HJmr5U5dyJ4QAtxHobU8kyMwqEmQTmpL9zDVfV1ZikvkVXgYrbwFEf6kLLmSU9c7tNaR8NHWdDCuNcHvnYb4cweuWq3t6oaPqumusmoAJxrekNHXYPNzwJ5eFjyKJz783PTGAJQUy1qy1tbCNog61rjvmGCrr1Ld2ejwgXxkAGQjBnBwXJzULPoH6vz6StKNZe2kgi58WQhENaoN3UV12dSzVmCFQAxbK4R4km71UTDhwb8ryYivwTLTQSWMhBwkLsY94QGFk").unwrap());
        assert_eq!(signer.account_id, AccountId::from_str("test").unwrap());
    }
}
