use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{PublicKey, SecretKey};

use near_account_id::AccountId;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyFile {
    pub account_id: AccountId,
    pub public_key: PublicKey,
    // Credential files generated which near cli works with have private_key
    // rather than secret_key field.  To make it possible to read those from
    // neard add private_key as an alias to this field so either will work.
    #[serde(alias = "private_key")]
    pub secret_key: SecretKey,
}

impl KeyFile {
    pub fn write_to_file(&self, path: &Path) -> io::Result<()> {
        let mut file = File::create(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Only the owner can read or write the file.
            let perm = std::fs::Permissions::from_mode(0o600);
            file.set_permissions(perm)?;
        }
        let str = serde_json::to_string_pretty(self)?;
        file.write_all(str.as_bytes())
    }

    pub fn from_file(path: &Path) -> io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use crate::KeyType;

    #[test]
    fn test_from_file() {
        fn load(contents: &[u8]) -> io::Result<KeyFile> {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.as_file().write_all(contents).unwrap();
            let result = KeyFile::from_file(tmp.path());
            tmp.close().unwrap();
            result
        }

        load(br#"{
            "account_id": "example",
            "public_key": "ed25519:6DSjZ8mvsRZDvFqFxo8tCKePG96omXW7eVYVSySmDk8e",
            "secret_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr"
        }"#).unwrap();

        load(br#"{
            "account_id": "example",
            "public_key": "falcon512:33Vfcg9qTD2bt1aftEEf5QxZxiyAoiLpVh4zoFpcwWyZboHggWrSozbHvsyzjvijBZkKvF1NuHCMs4eMNz5a7NFvcUJXhrAFm4ieBCDL3RtfydCs1ugzXW3NcU37ageJJE73ehfvY1D3fbTCAcHihRn8ZTbk5zLCVJb64iQK18FrhjcaMjQLL18sk52kbvJaJAtSKEgaV8ckcAxyc4abYEHcYK8ogyPsPZAfDeRm3vWWHEujfFy6YzTSK3PPJSj1ardUCpGh79dLPgQ5M7CCoJ9WHmgDEMDS9ZMquEjERDpEF3W4FfLzeP2w9soBArtihwT1XoHqNXjMQTMwhSdaoh6einrmHzYKisJQs6eFUbh8YfqHAHXrTvjiV4ob95ceYg4roerGSk65phffSC3xAvYZSd4zTc8qVUH6TkN6B97ekG1LVZ735asYXfRnxTQqLyU2SsrvMDnhvqmyV5gaS9KxMcJT18y4YmPv9KkmN9jKSqHM6vV3XWXJfK9HXL9XLCPyNqdU1ydUkXxYDcH1T6ccBVukLM7oDcBmESBQhfF3QdMz8zxfUPDN2nEaaKGqU9c1v8y7d98LCommDjVSz9rvTxXi5PBt4x1H64vh8wunCPjiqspJrgw8iK2KXnwqE2tsw52rpNZhYzpgX4J65gGDifd3DqgmSUCu5Gsq9BSc8F7VvoSL5q2gvJKP1pR8KsxNpQXnJgxdpXJSfTomkDPTyuZC5bZh1vNNZc1TLxo8uGG71G3kewNpw52ZijYTqsVDokbDEeLCxDttXM1MyN7fzuP2mUKevz4CcsBc9UVaXzukLXcm7yhQMTsBmuwisJ6dDdb7jLDg4hiMPxjmwhjMc4LT1ToAJf4GwzWBwFQ5LAT9NYz35kDT4xq4EDsJfV2xt8PxtvPEBG2D6zw2HsyLvs7YVaD2MBDvmDXLFuz7DAtuJxkW7Gfbwfocjn4G3drW3Qj3oGarZUbJipfien6WFthkUfmQqNBDZogR1BGPqP1CNVmyHE5Te3WyFhce43wAk79sYLRkes1oUbRdWYc1wtrEHYnwVQFkNRvLfZnqNrxVmVhp9NY385f43Vw4MqRdZkAH6mhyHDBXQ87krviR23uNAYAy9CZPrA1r16D3EA8o9j4h3LYDTWGhTroKsQDTp3dP12ngkkSxhSjVG6r44tKbm9YYk8jj9ELfRZDCMGYUWeoQbf6UX1aHiVHseA2Ka4RA4",
            "secret_key": "falcon512:2pvzFcxUVVFgEPaU2foDog2DWCzJa25MFZAnjkbFT3ygR9bDkmFKdoEXSU3ggwUzF8YY94FTKxr2uvGJuD5Be2MtgMkkqWLQmPp4tPVPmEEGHQtCVof2F24rSTDoPS2SV3K2RNqPa6KWUpEV8nSq4y47tnLCzsbJjvQw7aP5zNKVjoJbwTwjmKqsvH79XXhrZA2MEei3KB8kKkAM1iCfFgT5YP63DwFFzFMBHYDLCf1TP6bMJ8VbBHH3PmfWM3H6N1xhYRkX7aMsrSRzZSpWt5CFQXb1RAssSmNaGrJEEjcmQJp9A5hPWMcb8P2Bmamffsn7CaFNmvjiUNYHECrkhEgeLw1S15DTMku8BbGczC3fTjtiVeHg9Jh5atDATLcqfGgCkCMCpBgT7hJqo71sbVdbohDbngh8cegXEErnkLevRUC2iCyiyN6gRPne2x7nZrskAHL6oxTRAgZZLzhX2dPprcAHYzCL482sRwP3HgWY7UzjWVjto3nrmrxiXRfzyW7WgaGaRgu9rArPSAtmL3R9iu3nvaSHEB4TgDgxXdJALRCbFoMpJY4SZg3TqefhMz2GZkXvisUTAoW7GH4cVpfW3iAa4rPAkX1ASsbDqvmbJR1ssWXCogZL5QRAXC6VfEoBw4W63RTmZGTJkBAw8KL2Raw3hyApTvTMA4pn4iY7zC2hGfEmqVREzo6UqXbYNX5DxRYdRr9XAB5cdE1aMWa9BK6nTTyD7DeUmadLqWn9hgA7paTXh36ifuNCif79ySAV4zLPFwZCnZ7tvHCQpY4vNSsAjHzNjP6WpC3zNNj6CMdzN6tAdqzbtDhK8JgxpnNCceyQK8TiszXj6EYSqiURCwBWnAXXS6u7362DcvbVp9WzfWKnSFeb7kt5zgcVp7fgQUL1tQ9QrzKboa3z7UFdbKXhkVYLQZkkzJH2tLhCFTqHxLK1PmXySeCMGqUNx96qid4ZzAkRbg1CBx37docXTzWnP1UqUeC9Uah8pQAWsFrX4WML9SGVSoK1hqXi1NfTDP7hiLTtTi1sNrsTw3cz4GBvvu6ANpkjWNuhxZRmv9jvqnFzBSHcnagp2m29QhF8LUtom3m2craUanyBFLYqZewWqDSaGuP1V46n3XqDbAeC3TsBAPw375hCutPZ2kqffYVtfEMi3K8FKR8i6By7TDXyreMSLhTL8xNLRcdumoDaQ5tz1NhPFZtzhL9P58PQHQQj8bktut8wnbrr2ayJNYhaa4o7J5HarVoAXdLFaWY5xstsfSiCXfXxULTuQkgYoa52Un1Uzre3mqhboxzXhUV2Nbbj4t8YD5PHVoqmHvBdxJurhNUkkYsNCgVFksX6mNcTBSoD7Aj8vhVXZhnSaHkV5JBZMa3EAus3yhovLn34GDt8Ty8cLWFJL213m3r39Gq4Hx79Dq2T3Covgng9dNLSRiGyjna2r2AQc5gzY3rg9dAuW5h7aJVLJWkkr2NLZxgm1QB4bq7KtD7z5zkYVddFmbBp3rqPoECdZPf4ZgDgej8Q7qNpvzD87UZTtVYS4mZevAqZAQGSYrBQcRfJBHFRSTCMYXSMh1EdHDXEmR1XB1QVr6Tac2SzT5izSEnNPmVTpFZV4kNEddtJb4xDhck2wkS3qQ843fjHBbCgnnmCXbtUhz3VG5ZDMqJa7PPBbsp1ScMfUXKjCufMo935YGLXiVAYgiQXN29MbeqYhD7HTRJFpp5S1vm2Jzybek33ghFxpHp2BdSASbbMBM"
            }"#).unwrap();

        load(br#"{
            "account_id": "example",
            "public_key": "ed25519:6DSjZ8mvsRZDvFqFxo8tCKePG96omXW7eVYVSySmDk8e",
            "private_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr"
        }"#).unwrap();

        let err = load(br#"{
            "account_id": "example",
            "public_key": "ed25519:6DSjZ8mvsRZDvFqFxo8tCKePG96omXW7eVYVSySmDk8e",
            "secret_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr",
            "private_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr"
        }"#).map(|key| key.account_id).unwrap_err();

        //Falcon512 test
        load(br#"{
            "account_id": "example",
            "public_key": "ed25519:6DSjZ8mvsRZDvFqFxo8tCKePG96omXW7eVYVSySmDk8e",
            "private_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr"
        }"#).unwrap();


        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let inner_msg = err.into_inner().unwrap().to_string();
        assert!(inner_msg.contains("duplicate field"));
    }

    #[test]
    fn test_write_to_file() {
        //creating directory
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests");
        _ = std::fs::create_dir(path);
        // Falcon Keys
        let mut keyfile = KeyFile {
            account_id: AccountId::try_from(String::from("example.falcon")).unwrap(),
            secret_key: SecretKey::from_random(KeyType::FALCON512),
            public_key: PublicKey::empty(KeyType::FALCON512)
        };
        keyfile.public_key = keyfile.secret_key.public_key();
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/exemple_falcon_keys");
        match keyfile.write_to_file(path.as_path()) {
            Ok(_) => (),
            Err(_) => panic!("Writing of falcon512 keys to file failed"),
        }

        // ED25519 keys
        let mut keyfile = KeyFile {
            account_id: AccountId::try_from(String::from("example.ed25519")).unwrap(),
            secret_key: SecretKey::from_random(KeyType::ED25519),
            public_key: PublicKey::empty(KeyType::ED25519)
        };
        keyfile.public_key = keyfile.secret_key.public_key();
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/exemple_ed25519_keys");
        match keyfile.write_to_file(path.as_path()) {
            Ok(_) => (),
            Err(_) => panic!("Writing of ed25519 keys to file failed"),
        }

        //Secp256k1 keys
        let mut keyfile = KeyFile {
            account_id: AccountId::try_from(String::from("example.secp256k1")).unwrap(),
            secret_key: SecretKey::from_random(KeyType::SECP256K1),
            public_key: PublicKey::empty(KeyType::SECP256K1)
        };
        keyfile.public_key = keyfile.secret_key.public_key();
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests/exemple_secp256k1_keys");
        match keyfile.write_to_file(path.as_path()) {
            Ok(_) => (),
            Err(_) => panic!("Writing of secp256k1 keys to file failed"),
        }
    }
}

