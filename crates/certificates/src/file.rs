// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use crate::CertificateBundle;
use crate::CertificateRequest;
use crate::DatabaseTokenGroup;
use crate::ExemptionListTokenGroup;
use crate::HltTokenGroup;
use crate::KeyLoadError;
use crate::KeyPair;
use crate::KeyUnavailable;
use crate::KeyWriteError;
use crate::KeyserverTokenGroup;
use crate::PemDecodable;
use crate::PemEncodable;
use crate::PublicKey;
use crate::Role;
use crate::SynthesizerTokenGroup;
use crate::TokenBundle;
use crate::TokenGroup;

pub const CERT_EXT: &str = "cert";
pub const CERT_REQUEST_EXT: &str = "certr";
pub const EL_TOKEN_EXT: &str = "elt";
pub const EL_TOKEN_REQUEST_EXT: &str = "eltr";
pub const KEYSERVER_TOKEN_EXT: &str = "kt";
pub const KEYSERVER_TOKEN_REQUEST_EXT: &str = "ktr";
pub const DATABASE_TOKEN_EXT: &str = "dt";
pub const DATABASE_TOKEN_REQUEST_EXT: &str = "dtr";
pub const HLT_TOKEN_EXT: &str = "ht";
pub const HLT_TOKEN_REQUEST_EXT: &str = "htr";
pub const SYNTHESIZER_TOKEN_EXT: &str = "st";
pub const SYNTHESIZER_TOKEN_REQUEST_EXT: &str = "str";
pub const KEY_PRIV_EXT: &str = "priv";
pub const KEY_PUB_EXT: &str = "pub";

pub trait TokenExtension {
    const TOKEN_EXT: &'static str;
    const REQUEST_EXT: &'static str;
}

impl TokenExtension for ExemptionListTokenGroup {
    const TOKEN_EXT: &'static str = EL_TOKEN_EXT;
    const REQUEST_EXT: &'static str = EL_TOKEN_REQUEST_EXT;
}

impl TokenExtension for KeyserverTokenGroup {
    const TOKEN_EXT: &'static str = KEYSERVER_TOKEN_EXT;
    const REQUEST_EXT: &'static str = KEYSERVER_TOKEN_REQUEST_EXT;
}

impl TokenExtension for DatabaseTokenGroup {
    const TOKEN_EXT: &'static str = DATABASE_TOKEN_EXT;
    const REQUEST_EXT: &'static str = DATABASE_TOKEN_REQUEST_EXT;
}

impl TokenExtension for HltTokenGroup {
    const TOKEN_EXT: &'static str = HLT_TOKEN_EXT;
    const REQUEST_EXT: &'static str = HLT_TOKEN_REQUEST_EXT;
}

impl TokenExtension for SynthesizerTokenGroup {
    const TOKEN_EXT: &'static str = SYNTHESIZER_TOKEN_EXT;
    const REQUEST_EXT: &'static str = SYNTHESIZER_TOKEN_REQUEST_EXT;
}

pub fn save_certificate_bundle_to_file<R: Role>(
    cb: CertificateBundle<R>,
    path: &Path,
) -> Result<(), FileError> {
    validate_extension(path, CERT_EXT)?;

    let contents = cb
        .to_file_contents()
        .map_err(|_| FileError::CouldNotSaveCertificate)?;

    save_to_file(contents, path)
}

pub fn load_certificate_bundle_from_file<R: Role>(
    path: &Path,
) -> Result<CertificateBundle<R>, FileError> {
    validate_extension(path, CERT_EXT)?;
    let contents = fs::read(path).map_err(|_| FileError::CouldNotReadFromFile(path.to_owned()))?;
    CertificateBundle::from_file_contents(contents).map_err(|_| {
        FileError::UnexpectedCertFileContents(path.to_owned(), "certificate".to_owned())
    })
}

pub fn save_token_request_to_file<T: TokenGroup + TokenExtension>(
    tr: T::TokenRequest,
    path: &Path,
) -> Result<(), FileError> {
    validate_extension(path, T::REQUEST_EXT)?;

    let contents = tr
        .to_pem()
        .map_err(|_| FileError::CouldNotSaveTokenRequest)?;
    save_to_file(contents, path)
}

pub fn load_token_request_from_file<T: TokenGroup + TokenExtension>(
    path: &Path,
) -> Result<T::TokenRequest, FileError> {
    validate_extension(path, T::REQUEST_EXT)?;
    let contents = fs::read(path).map_err(|_| FileError::CouldNotReadFromFile(path.to_owned()))?;
    T::TokenRequest::from_pem(contents).map_err(|_| {
        FileError::UnexpectedTokenFileContents(path.to_owned(), "token request".to_owned())
    })
}

pub fn save_token_bundle_to_file<T: TokenGroup + TokenExtension>(
    tb: TokenBundle<T>,
    path: &Path,
) -> Result<(), FileError> {
    validate_extension(path, T::TOKEN_EXT)?;
    let contents = tb
        .to_file_contents()
        .map_err(|_| FileError::CouldNotSaveToken)?;

    save_to_file(contents, path)
}

pub fn load_token_bundle_from_file<T: TokenGroup + TokenExtension>(
    path: &Path,
) -> Result<TokenBundle<T>, FileError> {
    validate_extension(path, T::TOKEN_EXT)?;
    let contents = fs::read(path).map_err(|_| FileError::CouldNotReadFromFile(path.to_owned()))?;
    TokenBundle::from_file_contents(contents)
        .map_err(|_| FileError::UnexpectedTokenFileContents(path.to_owned(), "token".to_owned()))
}

pub fn save_cert_request_to_file<R: Role>(
    req: CertificateRequest<R, KeyUnavailable>,
    path: &Path,
) -> Result<(), FileError> {
    validate_extension(path, CERT_REQUEST_EXT)?;
    let contents = req
        .to_pem()
        .map_err(|_| FileError::CouldNotSaveCertificateRequest)?;
    save_to_file(contents, path)
}

pub fn load_cert_request_from_file<R: Role>(
    path: &Path,
) -> Result<CertificateRequest<R, KeyUnavailable>, FileError> {
    validate_extension(path, CERT_REQUEST_EXT)?;
    let contents = fs::read(path).map_err(|_| FileError::CouldNotReadFromFile(path.to_owned()))?;

    let request = CertificateRequest::from_pem(contents).map_err(|_| {
        FileError::UnexpectedCertFileContents(path.to_owned(), "certificate request".to_string())
    })?;
    Ok(request)
}

pub fn save_keypair_to_file<B: AsRef<[u8]>>(
    keypair: KeyPair,
    passphrase: B,
    path: &Path,
) -> Result<(PathBuf, PathBuf), FileError> {
    validate_extension(path, KEY_PRIV_EXT)?;

    let pub_path = path.with_extension(KEY_PUB_EXT);
    save_public_key_to_file(keypair.public_key(), &pub_path)?;

    let mut priv_file = create_new_file(path, FileMode::Sensitive)?;
    keypair.write_key(&mut priv_file, passphrase)?;
    Ok((path.to_path_buf(), pub_path))
}

pub fn load_keypair_from_file(
    path: &Path,
    passphrase: impl AsRef<[u8]>,
) -> Result<KeyPair, FileError> {
    validate_extension(path, KEY_PRIV_EXT)?;
    let contents = fs::read(path).map_err(|_| FileError::CouldNotReadFromFile(path.to_owned()))?;
    let kp = KeyPair::load_key(contents, passphrase)?;
    Ok(kp)
}

pub fn save_public_key_to_file(public_key: PublicKey, path: &Path) -> Result<(), FileError> {
    validate_extension(path, KEY_PUB_EXT)?;
    let pub_hex = public_key.to_string();
    let pem = public_key
        .to_pem()
        .map_err(|_| FileError::CouldNotSaveKey)?;
    let pub_contents = format!("{}\n{}", pub_hex, pem);

    save_to_file(pub_contents, path)?;
    Ok(())
}

pub fn load_public_key_from_file(path: &Path) -> Result<PublicKey, FileError> {
    validate_extension(path, KEY_PUB_EXT)?;
    let contents = fs::read(path).map_err(|_| FileError::CouldNotReadFromFile(path.to_owned()))?;
    let key = PublicKey::from_pem(contents).map_err(|_| FileError::PublicKeyError)?;
    Ok(key)
}

#[derive(PartialEq)]
enum FileMode {
    Regular,
    Sensitive,
}

fn create_new_file(path: &Path, mode: FileMode) -> Result<File, FileError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| FileError::FileCreation(path.to_owned(), err.to_string()))?;

    if mode == FileMode::Sensitive {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(PermissionsExt::from_mode(0o600))
                .map_err(|_| FileError::FilePermissionSetting(path.to_owned()))?;
        }
    }

    Ok(file)
}

fn save_to_file(contents: String, path: &Path) -> Result<(), FileError> {
    let mut file = create_new_file(path, FileMode::Regular)?;
    write!(file, "{}", contents).map_err(|err| FileError::FileWriteError(err.to_string()))?;
    Ok(())
}

fn validate_extension(path: &Path, expected_ext: &str) -> Result<(), FileError> {
    if let Some(ext) = path.extension() {
        if ext == expected_ext {
            return Ok(());
        }
    }
    Err(FileError::UnexpectedFileExtension(
        path.to_owned(),
        expected_ext.to_string(),
    ))
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum FileError {
    #[error("Unable to create the file {:?}. Error: {}.", .0, .1)]
    FileCreation(PathBuf, String),
    #[error("Unable to save certificate request.")]
    CouldNotSaveCertificateRequest,
    #[error("Unable to save certificate.")]
    CouldNotSaveCertificate,
    #[error("Unable to save token request.")]
    CouldNotSaveTokenRequest,
    #[error("Unable to save token.")]
    CouldNotSaveToken,
    #[error("Unable to save associated private key.")]
    CouldNotSaveKey,
    #[error("Unable to read from {:?}. Perhaps the file does not exist.", .0)]
    CouldNotReadFromFile(PathBuf),
    #[error("The supplied file {:?} does not have the expected extension ({}). Please check that you are using the correct tool, and that you are providing files in the correct order.", .0, .1)]
    UnexpectedFileExtension(PathBuf, String),
    #[error("Unable to load a {1} from the supplied file {0:?}. Perhaps the provided role type was not accurate.")]
    UnexpectedCertFileContents(PathBuf, String),
    #[error("Unable to load a {1} from the supplied file {0:?}. Perhaps the provided token type was not accurate.")]
    UnexpectedTokenFileContents(PathBuf, String),
    #[error("Public key supplied could not be parsed.")]
    PublicKeyError,
    #[error("Unable to load the private key.")]
    KeyLoadError(#[from] KeyLoadError),
    #[error("Unable to save the private key.")]
    KeyWriteError(#[from] KeyWriteError),
    #[error("Unable to write to file. {0}.")]
    FileWriteError(String),
    #[error("Unable to set appropriate permissions on file {0}.")]
    FilePermissionSetting(PathBuf),
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        fs::File,
        io::{self, BufRead},
        path::PathBuf,
        str::FromStr,
    };

    use doprf::party::KeyserverId;
    use tempfile::TempDir;

    use crate::{
        file::{
            load_cert_request_from_file, save_cert_request_to_file, save_token_request_to_file,
            FileError, CERT_REQUEST_EXT,
        },
        Builder, CertificateBundle, CertificateChain, DatabaseTokenGroup, DatabaseTokenRequest,
        Exemption, HltTokenGroup, HltTokenRequest, Infrastructure, IssuerAdditionalFields, KeyPair,
        KeyserverTokenGroup, KeyserverTokenRequest, PublicKey, RequestBuilder,
        SynthesizerTokenGroup, SynthesizerTokenRequest,
    };

    use crate::file::{
        load_certificate_bundle_from_file, load_public_key_from_file,
        save_certificate_bundle_to_file,
    };

    use super::save_keypair_to_file;

    #[test]
    fn can_save_cert_and_load_from_file() {
        let root_kp = KeyPair::new_random();
        let root_cert = RequestBuilder::<Exemption>::root_v1_builder(root_kp.public_key())
            .build()
            .load_key(root_kp)
            .unwrap()
            .self_sign(IssuerAdditionalFields::default())
            .unwrap();

        let int_kp = KeyPair::new_random();
        let int_req =
            RequestBuilder::<Exemption>::intermediate_v1_builder(int_kp.public_key()).build();

        let int_cert = root_cert
            .issue_cert(int_req, IssuerAdditionalFields::default())
            .unwrap();

        let mut chain = CertificateChain::<Exemption>::new();
        chain.add_item(root_cert);

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test_cert.cert");

        let cert_info = CertificateBundle::new(int_cert.clone(), Some(chain.clone()));

        save_certificate_bundle_to_file(cert_info, &path).unwrap();
        let cfc = load_certificate_bundle_from_file::<Exemption>(&path).unwrap();

        assert!(cfc.certs.contains(&int_cert));
    }

    #[test]
    fn saved_public_key_matches_private_key() {
        let temp = TempDir::new().unwrap();
        let key_path = temp.path().join("key.priv");

        let kp = KeyPair::new_random();
        let public_key = kp.public_key();
        let pw = "1234";

        let (_, pub_path) = save_keypair_to_file(kp, pw, &key_path).unwrap();

        let pubkey_from_file = load_public_key_from_file(&pub_path).unwrap();

        assert_eq!(public_key, pubkey_from_file)
    }

    #[test]
    fn saved_public_key_file_contains_hex_as_first_line() {
        let temp = TempDir::new().unwrap();
        let key_path = temp.path().join("key.priv");

        let kp = KeyPair::new_random();
        let public_key = kp.public_key();
        let pw = "1234";

        let (_, pub_path) = save_keypair_to_file(kp, pw, &key_path).unwrap();
        let file = File::open(pub_path).unwrap();
        let first_line = io::BufReader::new(file).lines().next().unwrap().unwrap();
        let pubkey_from_file_hex = PublicKey::from_str(&first_line).unwrap();

        assert_eq!(public_key, pubkey_from_file_hex)
    }

    #[cfg(unix)]
    #[test]
    fn private_key_saved_with_correct_permissions() {
        use std::{fs::metadata, os::unix::fs::PermissionsExt};

        let temp = TempDir::new().unwrap();
        let key_path = temp.path().join("key.priv");

        let kp = KeyPair::new_random();

        save_keypair_to_file(kp, "1234", &key_path).unwrap();
        let metadata = metadata(key_path).unwrap();

        let permissions = metadata.permissions();
        assert_eq!(
            permissions.mode() & 0o777,
            0o600,
            "File with .priv extension should be saved with 0600 permissions"
        );
    }

    #[cfg(unix)]
    #[test]
    fn public_key_saved_with_correct_permissions() {
        use std::{fs::metadata, os::unix::fs::PermissionsExt};

        let temp = TempDir::new().unwrap();
        let key_path = temp.path().join("key.priv");

        let kp = KeyPair::new_random();

        let (_, pub_path) = save_keypair_to_file(kp, "1234", &key_path).unwrap();
        let metadata = metadata(pub_path).unwrap();

        let permissions = metadata.permissions();
        let expected_permissions = calculate_expected_permissions();
        assert_eq!(
            permissions.mode() & 0o777,
            expected_permissions,
            "File not containing sensitive information should be saved using user's current umask"
        );
    }

    #[cfg(unix)]
    fn get_current_umask() -> u32 {
        unsafe {
            let umask = libc::umask(0);
            libc::umask(umask);
            umask as u32
        }
    }

    // umask specifies the bits to turn off, not the bits to keep, so
    // we need to flip its bits to apply it correctly to the default permissions
    #[cfg(unix)]
    fn calculate_expected_permissions() -> u32 {
        let umask = get_current_umask();
        let default_permissions = 0o666; // Default file permissions (rw-rw-rw-)
        default_permissions & !umask
    }

    #[test]
    fn cannot_save_cert_request_with_incorrect_extension() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("root.cert");

        let kp = KeyPair::new_random();
        let request = RequestBuilder::<Exemption>::intermediate_v1_builder(kp.public_key()).build();
        let result = save_cert_request_to_file(request, &request_path);
        let expected_err =
            FileError::UnexpectedFileExtension(request_path, CERT_REQUEST_EXT.to_owned());
        assert_eq!(result, Err(expected_err));
    }

    #[test]
    fn will_not_save_cert_request_when_parent_directory_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("subdir/root.certr");

        let kp = KeyPair::new_random();
        let request = RequestBuilder::<Exemption>::intermediate_v1_builder(kp.public_key()).build();
        let result = save_cert_request_to_file(request, &request_path);

        assert!(matches!(result, Err(FileError::FileCreation(_, _))));
    }

    #[test]
    fn will_not_save_cert_request_over_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");

        File::create(&request_path).unwrap();
        File::create(key_path).unwrap();

        let kp = KeyPair::new_random();
        let request = RequestBuilder::<Exemption>::intermediate_v1_builder(kp.public_key()).build();
        let result = save_cert_request_to_file(request, &request_path);

        assert!(matches!(result, Err(FileError::FileCreation(_, err)) if err.contains("exists")));
    }

    #[test]
    fn can_handle_attempt_to_save_cert_request_to_dev_null() {
        let request_path = PathBuf::from("/dev/null");

        let kp = KeyPair::new_random();

        let request = RequestBuilder::<Exemption>::root_v1_builder(kp.public_key())
            .allow_blinding(true)
            .build();

        save_cert_request_to_file(request, &request_path)
            .expect_err("should error when trying to save to /dev/null");
    }

    #[test]
    fn load_cert_handles_missing_file() {
        let cert = PathBuf::from("non/existent.cert");

        let result = load_certificate_bundle_from_file::<Infrastructure>(&cert);
        assert!(matches!(result, Err(FileError::CouldNotReadFromFile(..))));
    }

    #[test]
    fn load_cert_handles_incorrect_extension() {
        let path = PathBuf::from("key.priv");

        let result = load_certificate_bundle_from_file::<Infrastructure>(&path);
        assert!(matches!(
            result,
            Err(FileError::UnexpectedFileExtension(..))
        ));
    }

    #[test]
    fn load_cert_handles_unexpected_file_contents() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let cert_path = temp_path.join("root.cert");
        let key_path = temp_path.join("root.priv");

        let kp = KeyPair::new_random();
        save_keypair_to_file(kp, "12345678", &key_path).unwrap();
        let key_file_contents = fs::read_to_string(key_path).expect("Unable to read file");

        // Write the contents of the key to the cert file.
        fs::write(&cert_path, key_file_contents).expect("Unable to write file");

        let result = load_certificate_bundle_from_file::<Infrastructure>(&cert_path);
        assert!(matches!(
            result,
            Err(FileError::UnexpectedCertFileContents(..))
        ));
    }

    #[test]
    fn load_cert_request_handles_missing_file() {
        let temp_dir = TempDir::new().unwrap();
        let request_path = temp_dir.path().join("non/existent.certr");

        let result = load_cert_request_from_file::<Infrastructure>(&request_path);
        assert!(matches!(result, Err(FileError::CouldNotReadFromFile(..))));
    }

    #[test]
    fn load_cert_request_handles_incorrect_extension() {
        let path = PathBuf::from("key.priv");

        let result = load_cert_request_from_file::<Infrastructure>(&path);
        assert!(matches!(
            result,
            Err(FileError::UnexpectedFileExtension(..))
        ));
    }

    #[test]
    fn load_cert_request_handles_unexpected_file_contents() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        let request_path = temp_path.join("root.certr");
        let key_path = temp_path.join("root.priv");

        let kp = KeyPair::new_random();
        save_keypair_to_file(kp, "12345678", &key_path).unwrap();
        let key_file_contents = fs::read_to_string(key_path).expect("Unable to read file");

        // Write the contents of the key to the request file.
        fs::write(&request_path, key_file_contents).expect("Unable to write file");

        let result = load_cert_request_from_file::<Infrastructure>(&request_path);
        assert!(matches!(
            result,
            Err(FileError::UnexpectedCertFileContents(..))
        ));
    }

    #[test]
    fn keyserver_token_request_cannot_be_saved_with_incorrect_extension() {
        let destination_directory = TempDir::new().unwrap();
        //Incorrect extension
        let request_path = destination_directory.path().join("token.dtr");

        let kp = KeyPair::new_random();
        let keyserver_id = KeyserverId::try_from(1).unwrap();
        let token_request = KeyserverTokenRequest::v1_token_request(kp.public_key(), keyserver_id);
        let result =
            save_token_request_to_file::<KeyserverTokenGroup>(token_request, &request_path);

        assert!(
            matches!(result, Err(FileError::UnexpectedFileExtension(_, _))),
            "should not be able to save keyserver token to file with incorrect extension"
        );
    }

    #[test]
    fn database_token_request_cannot_be_saved_with_incorrect_extension() {
        let destination_directory = TempDir::new().unwrap();
        //Incorrect extension
        let request_path = destination_directory.path().join("token.ktr");

        let kp = KeyPair::new_random();
        let token_request = DatabaseTokenRequest::v1_token_request(kp.public_key());
        let result = save_token_request_to_file::<DatabaseTokenGroup>(token_request, &request_path);

        assert!(
            matches!(result, Err(FileError::UnexpectedFileExtension(_, _))),
            "should not be able to save database token to file with incorrect extension"
        );
    }

    #[test]
    fn hlt_token_request_cannot_be_saved_with_incorrect_extension() {
        let destination_directory = TempDir::new().unwrap();
        //Incorrect extension
        let request_path = destination_directory.path().join("token.ktr");

        let kp = KeyPair::new_random();
        let token_request = HltTokenRequest::v1_token_request(kp.public_key());
        let result = save_token_request_to_file::<HltTokenGroup>(token_request, &request_path);

        assert!(
            matches!(result, Err(FileError::UnexpectedFileExtension(_, _))),
            "should not be able to save HLT token to file with incorrect extension"
        );
    }

    #[test]
    fn synthesizer_token_request_cannot_be_saved_with_incorrect_extension() {
        let destination_directory = TempDir::new().unwrap();
        //Incorrect extension
        let request_path = destination_directory.path().join("token.dtr");

        let domain = "maker.synth".to_owned();
        let model = "XL".to_owned();
        let serial = "10AK".to_owned();
        let max_dna_base_pairs_per_day = 10_000_000u64;

        let kp = KeyPair::new_random();
        let token_request = SynthesizerTokenRequest::v1_token_request(
            kp.public_key(),
            domain,
            model,
            serial,
            max_dna_base_pairs_per_day,
            None,
        );
        let result =
            save_token_request_to_file::<SynthesizerTokenGroup>(token_request, &request_path);

        assert!(
            matches!(result, Err(FileError::UnexpectedFileExtension(_, _))),
            "should not be able to save synthesizer token to file with incorrect extension"
        );
    }
}
