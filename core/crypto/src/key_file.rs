use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{PublicKey, SecretKey};

use near_account_id::AccountId;

#[derive(Serialize, Deserialize)]
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
        let data = serde_json::to_string_pretty(self)?;
        let mut file = Self::create(path)?;
        file.write_all(data.as_bytes())
    }

    #[cfg(unix)]
    fn create(path: &Path) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::File::options().mode(0o600).write(true).create(true).open(path)
    }

    #[cfg(not(unix))]
    fn create(path: &Path) -> io::Result<File> {
        std::fs::File::create(path)
    }

    pub fn from_file(path: &Path) -> io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const ACCOUNT_ID: &'static str = "example";
    const SECRET_KEY: &'static str = "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr";
    const KEY_FILE_CONTENTS: &'static str = r#"{
  "account_id": "example",
  "public_key": "ed25519:6DSjZ8mvsRZDvFqFxo8tCKePG96omXW7eVYVSySmDk8e",
  "secret_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr"
}"#;

    const ACCOUNT_ID_FALCON: &'static str = "example.falcon";
    const SECRET_KEY_FALCON: &'static str = "falcon512:2pvzFcxUVVFgEPaU2foDog2DWCzJa25MFZAnjkbFT3ygR9bDkmFKdoEXSU3ggwUzF8YY94FTKxr2uvGJuD5Be2MtgMkkqWLQmPp4tPVPmEEGHQtCVof2F24rSTDoPS2SV3K2RNqPa6KWUpEV8nSq4y47tnLCzsbJjvQw7aP5zNKVjoJbwTwjmKqsvH79XXhrZA2MEei3KB8kKkAM1iCfFgT5YP63DwFFzFMBHYDLCf1TP6bMJ8VbBHH3PmfWM3H6N1xhYRkX7aMsrSRzZSpWt5CFQXb1RAssSmNaGrJEEjcmQJp9A5hPWMcb8P2Bmamffsn7CaFNmvjiUNYHECrkhEgeLw1S15DTMku8BbGczC3fTjtiVeHg9Jh5atDATLcqfGgCkCMCpBgT7hJqo71sbVdbohDbngh8cegXEErnkLevRUC2iCyiyN6gRPne2x7nZrskAHL6oxTRAgZZLzhX2dPprcAHYzCL482sRwP3HgWY7UzjWVjto3nrmrxiXRfzyW7WgaGaRgu9rArPSAtmL3R9iu3nvaSHEB4TgDgxXdJALRCbFoMpJY4SZg3TqefhMz2GZkXvisUTAoW7GH4cVpfW3iAa4rPAkX1ASsbDqvmbJR1ssWXCogZL5QRAXC6VfEoBw4W63RTmZGTJkBAw8KL2Raw3hyApTvTMA4pn4iY7zC2hGfEmqVREzo6UqXbYNX5DxRYdRr9XAB5cdE1aMWa9BK6nTTyD7DeUmadLqWn9hgA7paTXh36ifuNCif79ySAV4zLPFwZCnZ7tvHCQpY4vNSsAjHzNjP6WpC3zNNj6CMdzN6tAdqzbtDhK8JgxpnNCceyQK8TiszXj6EYSqiURCwBWnAXXS6u7362DcvbVp9WzfWKnSFeb7kt5zgcVp7fgQUL1tQ9QrzKboa3z7UFdbKXhkVYLQZkkzJH2tLhCFTqHxLK1PmXySeCMGqUNx96qid4ZzAkRbg1CBx37docXTzWnP1UqUeC9Uah8pQAWsFrX4WML9SGVSoK1hqXi1NfTDP7hiLTtTi1sNrsTw3cz4GBvvu6ANpkjWNuhxZRmv9jvqnFzBSHcnagp2m29QhF8LUtom3m2craUanyBFLYqZewWqDSaGuP1V46n3XqDbAeC3TsBAPw375hCutPZ2kqffYVtfEMi3K8FKR8i6By7TDXyreMSLhTL8xNLRcdumoDaQ5tz1NhPFZtzhL9P58PQHQQj8bktut8wnbrr2ayJNYhaa4o7J5HarVoAXdLFaWY5xstsfSiCXfXxULTuQkgYoa52Un1Uzre3mqhboxzXhUV2Nbbj4t8YD5PHVoqmHvBdxJurhNUkkYsNCgVFksX6mNcTBSoD7Aj8vhVXZhnSaHkV5JBZMa3EAus3yhovLn34GDt8Ty8cLWFJL213m3r39Gq4Hx79Dq2T3Covgng9dNLSRiGyjna2r2AQc5gzY3rg9dAuW5h7aJVLJWkkr2NLZxgm1QB4bq7KtD7z5zkYVddFmbBp3rqPoECdZPf4ZgDgej8Q7qNpvzD87UZTtVYS4mZevAqZAQGSYrBQcRfJBHFRSTCMYXSMh1EdHDXEmR1XB1QVr6Tac2SzT5izSEnNPmVTpFZV4kNEddtJb4xDhck2wkS3qQ843fjHBbCgnnmCXbtUhz3VG5ZDMqJa7PPBbsp1ScMfUXKjCufMo935YGLXiVAYgiQXN29MbeqYhD7HTRJFpp5S1vm2Jzybek33ghFxpHp2BdSASbbMBM";
    const KEY_FILE_CONTENTS_FALCON: &'static str = r#"{
  "account_id": "example.falcon",
  "public_key": "falcon512:33Vfcg9qTD2bt1aftEEf5QxZxiyAoiLpVh4zoFpcwWyZboHggWrSozbHvsyzjvijBZkKvF1NuHCMs4eMNz5a7NFvcUJXhrAFm4ieBCDL3RtfydCs1ugzXW3NcU37ageJJE73ehfvY1D3fbTCAcHihRn8ZTbk5zLCVJb64iQK18FrhjcaMjQLL18sk52kbvJaJAtSKEgaV8ckcAxyc4abYEHcYK8ogyPsPZAfDeRm3vWWHEujfFy6YzTSK3PPJSj1ardUCpGh79dLPgQ5M7CCoJ9WHmgDEMDS9ZMquEjERDpEF3W4FfLzeP2w9soBArtihwT1XoHqNXjMQTMwhSdaoh6einrmHzYKisJQs6eFUbh8YfqHAHXrTvjiV4ob95ceYg4roerGSk65phffSC3xAvYZSd4zTc8qVUH6TkN6B97ekG1LVZ735asYXfRnxTQqLyU2SsrvMDnhvqmyV5gaS9KxMcJT18y4YmPv9KkmN9jKSqHM6vV3XWXJfK9HXL9XLCPyNqdU1ydUkXxYDcH1T6ccBVukLM7oDcBmESBQhfF3QdMz8zxfUPDN2nEaaKGqU9c1v8y7d98LCommDjVSz9rvTxXi5PBt4x1H64vh8wunCPjiqspJrgw8iK2KXnwqE2tsw52rpNZhYzpgX4J65gGDifd3DqgmSUCu5Gsq9BSc8F7VvoSL5q2gvJKP1pR8KsxNpQXnJgxdpXJSfTomkDPTyuZC5bZh1vNNZc1TLxo8uGG71G3kewNpw52ZijYTqsVDokbDEeLCxDttXM1MyN7fzuP2mUKevz4CcsBc9UVaXzukLXcm7yhQMTsBmuwisJ6dDdb7jLDg4hiMPxjmwhjMc4LT1ToAJf4GwzWBwFQ5LAT9NYz35kDT4xq4EDsJfV2xt8PxtvPEBG2D6zw2HsyLvs7YVaD2MBDvmDXLFuz7DAtuJxkW7Gfbwfocjn4G3drW3Qj3oGarZUbJipfien6WFthkUfmQqNBDZogR1BGPqP1CNVmyHE5Te3WyFhce43wAk79sYLRkes1oUbRdWYc1wtrEHYnwVQFkNRvLfZnqNrxVmVhp9NY385f43Vw4MqRdZkAH6mhyHDBXQ87krviR23uNAYAy9CZPrA1r16D3EA8o9j4h3LYDTWGhTroKsQDTp3dP12ngkkSxhSjVG6r44tKbm9YYk8jj9ELfRZDCMGYUWeoQbf6UX1aHiVHseA2Ka4RA4",
  "secret_key": "falcon512:2pvzFcxUVVFgEPaU2foDog2DWCzJa25MFZAnjkbFT3ygR9bDkmFKdoEXSU3ggwUzF8YY94FTKxr2uvGJuD5Be2MtgMkkqWLQmPp4tPVPmEEGHQtCVof2F24rSTDoPS2SV3K2RNqPa6KWUpEV8nSq4y47tnLCzsbJjvQw7aP5zNKVjoJbwTwjmKqsvH79XXhrZA2MEei3KB8kKkAM1iCfFgT5YP63DwFFzFMBHYDLCf1TP6bMJ8VbBHH3PmfWM3H6N1xhYRkX7aMsrSRzZSpWt5CFQXb1RAssSmNaGrJEEjcmQJp9A5hPWMcb8P2Bmamffsn7CaFNmvjiUNYHECrkhEgeLw1S15DTMku8BbGczC3fTjtiVeHg9Jh5atDATLcqfGgCkCMCpBgT7hJqo71sbVdbohDbngh8cegXEErnkLevRUC2iCyiyN6gRPne2x7nZrskAHL6oxTRAgZZLzhX2dPprcAHYzCL482sRwP3HgWY7UzjWVjto3nrmrxiXRfzyW7WgaGaRgu9rArPSAtmL3R9iu3nvaSHEB4TgDgxXdJALRCbFoMpJY4SZg3TqefhMz2GZkXvisUTAoW7GH4cVpfW3iAa4rPAkX1ASsbDqvmbJR1ssWXCogZL5QRAXC6VfEoBw4W63RTmZGTJkBAw8KL2Raw3hyApTvTMA4pn4iY7zC2hGfEmqVREzo6UqXbYNX5DxRYdRr9XAB5cdE1aMWa9BK6nTTyD7DeUmadLqWn9hgA7paTXh36ifuNCif79ySAV4zLPFwZCnZ7tvHCQpY4vNSsAjHzNjP6WpC3zNNj6CMdzN6tAdqzbtDhK8JgxpnNCceyQK8TiszXj6EYSqiURCwBWnAXXS6u7362DcvbVp9WzfWKnSFeb7kt5zgcVp7fgQUL1tQ9QrzKboa3z7UFdbKXhkVYLQZkkzJH2tLhCFTqHxLK1PmXySeCMGqUNx96qid4ZzAkRbg1CBx37docXTzWnP1UqUeC9Uah8pQAWsFrX4WML9SGVSoK1hqXi1NfTDP7hiLTtTi1sNrsTw3cz4GBvvu6ANpkjWNuhxZRmv9jvqnFzBSHcnagp2m29QhF8LUtom3m2craUanyBFLYqZewWqDSaGuP1V46n3XqDbAeC3TsBAPw375hCutPZ2kqffYVtfEMi3K8FKR8i6By7TDXyreMSLhTL8xNLRcdumoDaQ5tz1NhPFZtzhL9P58PQHQQj8bktut8wnbrr2ayJNYhaa4o7J5HarVoAXdLFaWY5xstsfSiCXfXxULTuQkgYoa52Un1Uzre3mqhboxzXhUV2Nbbj4t8YD5PHVoqmHvBdxJurhNUkkYsNCgVFksX6mNcTBSoD7Aj8vhVXZhnSaHkV5JBZMa3EAus3yhovLn34GDt8Ty8cLWFJL213m3r39Gq4Hx79Dq2T3Covgng9dNLSRiGyjna2r2AQc5gzY3rg9dAuW5h7aJVLJWkkr2NLZxgm1QB4bq7KtD7z5zkYVddFmbBp3rqPoECdZPf4ZgDgej8Q7qNpvzD87UZTtVYS4mZevAqZAQGSYrBQcRfJBHFRSTCMYXSMh1EdHDXEmR1XB1QVr6Tac2SzT5izSEnNPmVTpFZV4kNEddtJb4xDhck2wkS3qQ843fjHBbCgnnmCXbtUhz3VG5ZDMqJa7PPBbsp1ScMfUXKjCufMo935YGLXiVAYgiQXN29MbeqYhD7HTRJFpp5S1vm2Jzybek33ghFxpHp2BdSASbbMBM"
}"#;

    #[test]
    fn test_to_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("key-file");

        let account_id = ACCOUNT_ID.parse().unwrap();
        let secret_key: SecretKey = SECRET_KEY.parse().unwrap();
        let public_key = secret_key.public_key().clone();
        let key = KeyFile { account_id, public_key, secret_key };
        key.write_to_file(&path).unwrap();

        assert_eq!(KEY_FILE_CONTENTS, std::fs::read_to_string(&path).unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let got = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(0o600, got & 0o777);
        }
    }

    #[test]
    fn test_to_file_falcon() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("key-file");

        let account_id = ACCOUNT_ID_FALCON.parse().unwrap();
        let secret_key: SecretKey = SECRET_KEY_FALCON.parse().unwrap();
        let public_key = secret_key.public_key().clone();
        let key = KeyFile { account_id, public_key, secret_key };
        key.write_to_file(&path).unwrap();

        assert_eq!(KEY_FILE_CONTENTS_FALCON, std::fs::read_to_string(&path).unwrap());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let got = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(0o600, got & 0o777);
        }
    }

    #[test]
    fn test_from_file() {
        fn load(contents: &[u8]) -> io::Result<()> {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.as_file().write_all(contents).unwrap();
            let result = KeyFile::from_file(tmp.path());
            tmp.close().unwrap();

            result.map(|key| {
                assert_eq!(ACCOUNT_ID, key.account_id.to_string());
                let secret_key: SecretKey = SECRET_KEY.parse().unwrap();
                assert_eq!(secret_key, key.secret_key);
                assert_eq!(secret_key.public_key(), key.public_key);
                ()
            })
        }

        load(KEY_FILE_CONTENTS.as_bytes()).unwrap();

        // Test private_key alias for secret_key works.
        let contents = KEY_FILE_CONTENTS.replace("secret_key", "private_key");
        load(contents.as_bytes()).unwrap();

        // Test private_key is mutually exclusive with secret_key.
        let err = load(br#"{
            "account_id": "example",
            "public_key": "ed25519:6DSjZ8mvsRZDvFqFxo8tCKePG96omXW7eVYVSySmDk8e",
            "secret_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr",
            "private_key": "ed25519:3D4YudUahN1nawWogh8pAKSj92sUNMdbZGjn7kERKzYoTy8tnFQuwoGUC51DowKqorvkr2pytJSnwuSbsNVfqygr"
        }"#).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let inner_msg = err.into_inner().unwrap().to_string();
        assert!(inner_msg.contains("duplicate field"));
    }

    #[test]
    fn test_from_file_falcon() {
        fn load(contents: &[u8]) -> io::Result<()> {
            let tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.as_file().write_all(contents).unwrap();
            let result = KeyFile::from_file(tmp.path());
            tmp.close().unwrap();

            result.map(|key| {
                assert_eq!(ACCOUNT_ID_FALCON, key.account_id.to_string());
                let secret_key: SecretKey = SECRET_KEY_FALCON.parse().unwrap();
                assert_eq!(secret_key, key.secret_key);
                assert_eq!(secret_key.public_key(), key.public_key);
                ()
            })
        }

        load(KEY_FILE_CONTENTS_FALCON.as_bytes()).unwrap();

        // Test private_key alias for secret_key works.
        let contents = KEY_FILE_CONTENTS_FALCON.replace("secret_key", "private_key");
        load(contents.as_bytes()).unwrap();

        // Test private_key is mutually exclusive with secret_key.
        let err = load(br#"{
            "account_id": "example.falcon",
            "public_key": "falcon512:33Vfcg9qTD2bt1aftEEf5QxZxiyAoiLpVh4zoFpcwWyZboHggWrSozbHvsyzjvijBZkKvF1NuHCMs4eMNz5a7NFvcUJXhrAFm4ieBCDL3RtfydCs1ugzXW3NcU37ageJJE73ehfvY1D3fbTCAcHihRn8ZTbk5zLCVJb64iQK18FrhjcaMjQLL18sk52kbvJaJAtSKEgaV8ckcAxyc4abYEHcYK8ogyPsPZAfDeRm3vWWHEujfFy6YzTSK3PPJSj1ardUCpGh79dLPgQ5M7CCoJ9WHmgDEMDS9ZMquEjERDpEF3W4FfLzeP2w9soBArtihwT1XoHqNXjMQTMwhSdaoh6einrmHzYKisJQs6eFUbh8YfqHAHXrTvjiV4ob95ceYg4roerGSk65phffSC3xAvYZSd4zTc8qVUH6TkN6B97ekG1LVZ735asYXfRnxTQqLyU2SsrvMDnhvqmyV5gaS9KxMcJT18y4YmPv9KkmN9jKSqHM6vV3XWXJfK9HXL9XLCPyNqdU1ydUkXxYDcH1T6ccBVukLM7oDcBmESBQhfF3QdMz8zxfUPDN2nEaaKGqU9c1v8y7d98LCommDjVSz9rvTxXi5PBt4x1H64vh8wunCPjiqspJrgw8iK2KXnwqE2tsw52rpNZhYzpgX4J65gGDifd3DqgmSUCu5Gsq9BSc8F7VvoSL5q2gvJKP1pR8KsxNpQXnJgxdpXJSfTomkDPTyuZC5bZh1vNNZc1TLxo8uGG71G3kewNpw52ZijYTqsVDokbDEeLCxDttXM1MyN7fzuP2mUKevz4CcsBc9UVaXzukLXcm7yhQMTsBmuwisJ6dDdb7jLDg4hiMPxjmwhjMc4LT1ToAJf4GwzWBwFQ5LAT9NYz35kDT4xq4EDsJfV2xt8PxtvPEBG2D6zw2HsyLvs7YVaD2MBDvmDXLFuz7DAtuJxkW7Gfbwfocjn4G3drW3Qj3oGarZUbJipfien6WFthkUfmQqNBDZogR1BGPqP1CNVmyHE5Te3WyFhce43wAk79sYLRkes1oUbRdWYc1wtrEHYnwVQFkNRvLfZnqNrxVmVhp9NY385f43Vw4MqRdZkAH6mhyHDBXQ87krviR23uNAYAy9CZPrA1r16D3EA8o9j4h3LYDTWGhTroKsQDTp3dP12ngkkSxhSjVG6r44tKbm9YYk8jj9ELfRZDCMGYUWeoQbf6UX1aHiVHseA2Ka4RA4",
            "secret_key": "falcon512:2pvzFcxUVVFgEPaU2foDog2DWCzJa25MFZAnjkbFT3ygR9bDkmFKdoEXSU3ggwUzF8YY94FTKxr2uvGJuD5Be2MtgMkkqWLQmPp4tPVPmEEGHQtCVof2F24rSTDoPS2SV3K2RNqPa6KWUpEV8nSq4y47tnLCzsbJjvQw7aP5zNKVjoJbwTwjmKqsvH79XXhrZA2MEei3KB8kKkAM1iCfFgT5YP63DwFFzFMBHYDLCf1TP6bMJ8VbBHH3PmfWM3H6N1xhYRkX7aMsrSRzZSpWt5CFQXb1RAssSmNaGrJEEjcmQJp9A5hPWMcb8P2Bmamffsn7CaFNmvjiUNYHECrkhEgeLw1S15DTMku8BbGczC3fTjtiVeHg9Jh5atDATLcqfGgCkCMCpBgT7hJqo71sbVdbohDbngh8cegXEErnkLevRUC2iCyiyN6gRPne2x7nZrskAHL6oxTRAgZZLzhX2dPprcAHYzCL482sRwP3HgWY7UzjWVjto3nrmrxiXRfzyW7WgaGaRgu9rArPSAtmL3R9iu3nvaSHEB4TgDgxXdJALRCbFoMpJY4SZg3TqefhMz2GZkXvisUTAoW7GH4cVpfW3iAa4rPAkX1ASsbDqvmbJR1ssWXCogZL5QRAXC6VfEoBw4W63RTmZGTJkBAw8KL2Raw3hyApTvTMA4pn4iY7zC2hGfEmqVREzo6UqXbYNX5DxRYdRr9XAB5cdE1aMWa9BK6nTTyD7DeUmadLqWn9hgA7paTXh36ifuNCif79ySAV4zLPFwZCnZ7tvHCQpY4vNSsAjHzNjP6WpC3zNNj6CMdzN6tAdqzbtDhK8JgxpnNCceyQK8TiszXj6EYSqiURCwBWnAXXS6u7362DcvbVp9WzfWKnSFeb7kt5zgcVp7fgQUL1tQ9QrzKboa3z7UFdbKXhkVYLQZkkzJH2tLhCFTqHxLK1PmXySeCMGqUNx96qid4ZzAkRbg1CBx37docXTzWnP1UqUeC9Uah8pQAWsFrX4WML9SGVSoK1hqXi1NfTDP7hiLTtTi1sNrsTw3cz4GBvvu6ANpkjWNuhxZRmv9jvqnFzBSHcnagp2m29QhF8LUtom3m2craUanyBFLYqZewWqDSaGuP1V46n3XqDbAeC3TsBAPw375hCutPZ2kqffYVtfEMi3K8FKR8i6By7TDXyreMSLhTL8xNLRcdumoDaQ5tz1NhPFZtzhL9P58PQHQQj8bktut8wnbrr2ayJNYhaa4o7J5HarVoAXdLFaWY5xstsfSiCXfXxULTuQkgYoa52Un1Uzre3mqhboxzXhUV2Nbbj4t8YD5PHVoqmHvBdxJurhNUkkYsNCgVFksX6mNcTBSoD7Aj8vhVXZhnSaHkV5JBZMa3EAus3yhovLn34GDt8Ty8cLWFJL213m3r39Gq4Hx79Dq2T3Covgng9dNLSRiGyjna2r2AQc5gzY3rg9dAuW5h7aJVLJWkkr2NLZxgm1QB4bq7KtD7z5zkYVddFmbBp3rqPoECdZPf4ZgDgej8Q7qNpvzD87UZTtVYS4mZevAqZAQGSYrBQcRfJBHFRSTCMYXSMh1EdHDXEmR1XB1QVr6Tac2SzT5izSEnNPmVTpFZV4kNEddtJb4xDhck2wkS3qQ843fjHBbCgnnmCXbtUhz3VG5ZDMqJa7PPBbsp1ScMfUXKjCufMo935YGLXiVAYgiQXN29MbeqYhD7HTRJFpp5S1vm2Jzybek33ghFxpHp2BdSASbbMBM",
            "private_key": "falcon512:2pvzFcxUVVFgEPaU2foDog2DWCzJa25MFZAnjkbFT3ygR9bDkmFKdoEXSU3ggwUzF8YY94FTKxr2uvGJuD5Be2MtgMkkqWLQmPp4tPVPmEEGHQtCVof2F24rSTDoPS2SV3K2RNqPa6KWUpEV8nSq4y47tnLCzsbJjvQw7aP5zNKVjoJbwTwjmKqsvH79XXhrZA2MEei3KB8kKkAM1iCfFgT5YP63DwFFzFMBHYDLCf1TP6bMJ8VbBHH3PmfWM3H6N1xhYRkX7aMsrSRzZSpWt5CFQXb1RAssSmNaGrJEEjcmQJp9A5hPWMcb8P2Bmamffsn7CaFNmvjiUNYHECrkhEgeLw1S15DTMku8BbGczC3fTjtiVeHg9Jh5atDATLcqfGgCkCMCpBgT7hJqo71sbVdbohDbngh8cegXEErnkLevRUC2iCyiyN6gRPne2x7nZrskAHL6oxTRAgZZLzhX2dPprcAHYzCL482sRwP3HgWY7UzjWVjto3nrmrxiXRfzyW7WgaGaRgu9rArPSAtmL3R9iu3nvaSHEB4TgDgxXdJALRCbFoMpJY4SZg3TqefhMz2GZkXvisUTAoW7GH4cVpfW3iAa4rPAkX1ASsbDqvmbJR1ssWXCogZL5QRAXC6VfEoBw4W63RTmZGTJkBAw8KL2Raw3hyApTvTMA4pn4iY7zC2hGfEmqVREzo6UqXbYNX5DxRYdRr9XAB5cdE1aMWa9BK6nTTyD7DeUmadLqWn9hgA7paTXh36ifuNCif79ySAV4zLPFwZCnZ7tvHCQpY4vNSsAjHzNjP6WpC3zNNj6CMdzN6tAdqzbtDhK8JgxpnNCceyQK8TiszXj6EYSqiURCwBWnAXXS6u7362DcvbVp9WzfWKnSFeb7kt5zgcVp7fgQUL1tQ9QrzKboa3z7UFdbKXhkVYLQZkkzJH2tLhCFTqHxLK1PmXySeCMGqUNx96qid4ZzAkRbg1CBx37docXTzWnP1UqUeC9Uah8pQAWsFrX4WML9SGVSoK1hqXi1NfTDP7hiLTtTi1sNrsTw3cz4GBvvu6ANpkjWNuhxZRmv9jvqnFzBSHcnagp2m29QhF8LUtom3m2craUanyBFLYqZewWqDSaGuP1V46n3XqDbAeC3TsBAPw375hCutPZ2kqffYVtfEMi3K8FKR8i6By7TDXyreMSLhTL8xNLRcdumoDaQ5tz1NhPFZtzhL9P58PQHQQj8bktut8wnbrr2ayJNYhaa4o7J5HarVoAXdLFaWY5xstsfSiCXfXxULTuQkgYoa52Un1Uzre3mqhboxzXhUV2Nbbj4t8YD5PHVoqmHvBdxJurhNUkkYsNCgVFksX6mNcTBSoD7Aj8vhVXZhnSaHkV5JBZMa3EAus3yhovLn34GDt8Ty8cLWFJL213m3r39Gq4Hx79Dq2T3Covgng9dNLSRiGyjna2r2AQc5gzY3rg9dAuW5h7aJVLJWkkr2NLZxgm1QB4bq7KtD7z5zkYVddFmbBp3rqPoECdZPf4ZgDgej8Q7qNpvzD87UZTtVYS4mZevAqZAQGSYrBQcRfJBHFRSTCMYXSMh1EdHDXEmR1XB1QVr6Tac2SzT5izSEnNPmVTpFZV4kNEddtJb4xDhck2wkS3qQ843fjHBbCgnnmCXbtUhz3VG5ZDMqJa7PPBbsp1ScMfUXKjCufMo935YGLXiVAYgiQXN29MbeqYhD7HTRJFpp5S1vm2Jzybek33ghFxpHp2BdSASbbMBM"
        }"#).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let inner_msg = err.into_inner().unwrap().to_string();
        assert!(inner_msg.contains("duplicate field"));
    }
}
