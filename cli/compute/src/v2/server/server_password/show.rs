// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Show Server Password command (with optional RSA decryption)

use clap::Args;
use dialoguer::Password;
use std::path::{Path, PathBuf};
use tracing::info;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use openstack_cli_core::cli::CliArgs;
use openstack_cli_core::error::OpenStackCliError;
use openstack_cli_core::output::OutputProcessor;
use openstack_sdk::AsyncOpenStack;

use openstack_sdk::api::QueryAsync;
use openstack_sdk::api::compute::v2::server::server_password::get;
use openstack_types::compute::v2::server::server_password::response;

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use ssh_key::PrivateKey;

/// Shows the administrative password for a server.
///
/// Without `--private-key` the raw base64-encoded ciphertext is displayed.
/// With `--private-key` the password is decrypted and the plaintext is shown.
#[derive(Args)]
#[command(about = "Show Server Password")]
pub struct ShowCommand {
    /// Request Query parameters
    #[command(flatten)]
    query: QueryParameters,

    /// Path parameters
    #[command(flatten)]
    path: PathParameters,

    /// Path to SSH private key file used to decrypt the password.
    /// Supports OpenSSH, PEM RSA, and PKCS#8 formats.
    /// If the key is passphrase-protected you will be prompted interactively.
    #[arg(
        long,
        value_name = "PATH",
        value_hint = clap::ValueHint::FilePath,
        help_heading = "Decryption"
    )]
    private_key: Option<PathBuf>,
}

/// Query parameters
#[derive(Args)]
struct QueryParameters {}

/// Path parameters
#[derive(Args)]
struct PathParameters {
    /// server_id parameter for /v2.1/servers/{server_id}/os-server-password API
    #[arg(
        help_heading = "Path parameters",
        id = "path_param_server_id",
        value_name = "SERVER_ID"
    )]
    server_id: String,
}

impl ShowCommand {
    /// Perform command action
    pub async fn take_action<C: CliArgs>(
        &self,
        parsed_args: &C,
        client: &mut AsyncOpenStack,
    ) -> Result<(), OpenStackCliError> {
        info!("Show ServerPassword");

        let op = OutputProcessor::from_args(
            parsed_args,
            Some("compute.server/server_password"),
            Some("get"),
        );
        op.validate_args(parsed_args)?;

        let mut ep_builder = get::Request::builder();
        ep_builder.server_id(&self.path.server_id);
        let ep = ep_builder
            .build()
            .map_err(|x| OpenStackCliError::EndpointBuild(x.to_string()))?;

        let data: serde_json::Value = ep.query_async(client).await?;

        let encrypted_b64 = data
            .get("password")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // No private key provided or no password set — display as-is.
        let Some(key_path) = &self.private_key else {
            op.output_single::<response::get::ServerPasswordResponse>(data)?;
            op.show_command_hint()?;
            return Ok(());
        };

        if encrypted_b64.is_empty() {
            op.output_single::<response::get::ServerPasswordResponse>(data)?;
            op.show_command_hint()?;
            return Ok(());
        }

        let plaintext = decrypt_password(key_path, encrypted_b64)?;
        let decrypted = serde_json::json!({ "password": plaintext });
        op.output_single::<response::get::ServerPasswordResponse>(decrypted)?;
        op.show_command_hint()?;
        Ok(())
    }
}

/// Load an RSA private key from a PEM file.
///
/// Supports:
/// - OpenSSH format (`BEGIN OPENSSH PRIVATE KEY`) — passphrase-protected keys
///   trigger an interactive prompt.
/// - Traditional PEM RSA (`BEGIN RSA PRIVATE KEY`)
/// - PKCS#8 PEM (`BEGIN PRIVATE KEY`)
///
/// Encrypted traditional PEM returns a helpful conversion error.
fn load_rsa_key(key_path: &Path) -> Result<RsaPrivateKey, OpenStackCliError> {
    let content = std::fs::read_to_string(key_path)?;

    if content.contains("BEGIN OPENSSH PRIVATE KEY") {
        let private_key = PrivateKey::from_openssh(&content).map_err(|e| {
            OpenStackCliError::InputParameters(format!("failed to parse SSH key: {e}"))
        })?;

        let private_key = if private_key.is_encrypted() {
            let passphrase = Password::new()
                .with_prompt("SSH key passphrase")
                .interact()?;
            private_key
                .decrypt(passphrase.as_bytes())
                .map_err(|e| {
                    OpenStackCliError::InputParameters(format!(
                        "failed to decrypt SSH key (wrong passphrase?): {e}"
                    ))
                })?
        } else {
            private_key
        };

        let rsa_keypair = private_key.key_data().rsa().ok_or_else(|| {
            OpenStackCliError::InputParameters(
                "private key must be RSA (Ed25519/ECDSA keys are not supported)".into(),
            )
        })?;

        RsaPrivateKey::try_from(rsa_keypair).map_err(|e| {
            OpenStackCliError::InputParameters(format!("failed to extract RSA key: {e}"))
        })
    } else if content.contains("BEGIN RSA PRIVATE KEY") {
        RsaPrivateKey::from_pkcs1_pem(&content).map_err(|e| {
            OpenStackCliError::InputParameters(format!("failed to parse RSA PEM key: {e}"))
        })
    } else if content.contains("BEGIN PRIVATE KEY") {
        RsaPrivateKey::from_pkcs8_pem(&content).map_err(|e| {
            OpenStackCliError::InputParameters(format!("failed to parse PKCS#8 key: {e}"))
        })
    } else if content.contains("ENCRYPTED") {
        Err(OpenStackCliError::InputParameters(
            "encrypted traditional PEM keys are not supported; \
             convert first with: ssh-keygen -p -m OpenSSH -f <key>"
                .into(),
        ))
    } else {
        Err(OpenStackCliError::InputParameters(
            "unrecognized private key format (expected OpenSSH, PEM RSA, or PKCS#8)".into(),
        ))
    }
}

/// Base64-decode and RSA PKCS#1 v1.5 decrypt a Nova server password.
fn decrypt_password(key_path: &Path, encrypted_b64: &str) -> Result<String, OpenStackCliError> {
    let rsa_key = load_rsa_key(key_path)?;

    let ciphertext = BASE64.decode(encrypted_b64)?;

    let plaintext_bytes = rsa_key.decrypt(Pkcs1v15Encrypt, &ciphertext).map_err(|_| {
        OpenStackCliError::InputParameters(
            "failed to decrypt password — is this the right key?".into(),
        )
    })?;

    String::from_utf8(plaintext_bytes).map_err(|_| {
        OpenStackCliError::InputParameters("decrypted password is not valid UTF-8".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::NamedTempFile;

    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding as Pkcs1LineEnding};
    use rsa::pkcs8::{EncodePrivateKey, LineEnding as Pkcs8LineEnding};
    use rsa::{RsaPublicKey, rand_core::OsRng};

    /// Generate a 1024-bit RSA key pair for tests (small = fast).
    fn make_test_keypair() -> (RsaPrivateKey, RsaPublicKey) {
        let private = RsaPrivateKey::new(&mut OsRng, 1024).expect("key generation");
        let public = RsaPublicKey::from(&private);
        (private, public)
    }

    /// Encrypt `plaintext` with `public_key` using PKCS#1 v1.5 and return base64.
    fn nova_encrypt(public_key: &RsaPublicKey, plaintext: &str) -> String {
        let ct = public_key
            .encrypt(&mut OsRng, Pkcs1v15Encrypt, plaintext.as_bytes())
            .expect("encrypt");
        BASE64.encode(ct)
    }

    // ── PKCS#1 PEM ───────────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_pkcs1_pem() {
        let (priv_key, pub_key) = make_test_keypair();
        let encrypted_b64 = nova_encrypt(&pub_key, "s3cr3t");

        let pem = priv_key
            .to_pkcs1_pem(Pkcs1LineEnding::LF)
            .expect("pkcs1 pem");
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(pem.as_bytes()).expect("write");

        assert_eq!(
            decrypt_password(f.path(), &encrypted_b64).expect("decrypt"),
            "s3cr3t"
        );
    }

    // ── PKCS#8 PEM ───────────────────────────────────────────────────────────

    #[test]
    fn test_decrypt_pkcs8_pem() {
        let (priv_key, pub_key) = make_test_keypair();
        let encrypted_b64 = nova_encrypt(&pub_key, "p@ssw0rd");

        let pem = priv_key
            .to_pkcs8_pem(Pkcs8LineEnding::LF)
            .expect("pkcs8 pem");
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(pem.as_bytes()).expect("write");

        assert_eq!(
            decrypt_password(f.path(), &encrypted_b64).expect("decrypt"),
            "p@ssw0rd"
        );
    }

    // ── Error cases ──────────────────────────────────────────────────────────

    #[test]
    fn test_wrong_key_returns_error() {
        let (_, pub_key) = make_test_keypair();
        let encrypted_b64 = nova_encrypt(&pub_key, "secret");

        let (wrong_priv, _) = make_test_keypair();
        let pem = wrong_priv
            .to_pkcs1_pem(Pkcs1LineEnding::LF)
            .expect("pkcs1 pem");
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(pem.as_bytes()).expect("write");

        let err = decrypt_password(f.path(), &encrypted_b64).expect_err("should fail");
        assert!(
            matches!(err, OpenStackCliError::InputParameters(_)),
            "expected InputParameters, got {err:?}"
        );
    }

    #[test]
    fn test_invalid_base64_returns_error() {
        let (priv_key, _) = make_test_keypair();
        let pem = priv_key
            .to_pkcs1_pem(Pkcs1LineEnding::LF)
            .expect("pkcs1 pem");
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(pem.as_bytes()).expect("write");

        let err = decrypt_password(f.path(), "not!!valid!!base64").expect_err("should fail");
        assert!(
            matches!(err, OpenStackCliError::Base64Decode(_)),
            "expected Base64Decode, got {err:?}"
        );
    }

    #[test]
    fn test_encrypted_traditional_pem_returns_helpful_error() {
        let content =
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nfake\n-----END ENCRYPTED PRIVATE KEY-----\n";
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(content).expect("write");

        let err = load_rsa_key(f.path()).expect_err("should fail");
        match err {
            OpenStackCliError::InputParameters(msg) => {
                assert!(
                    msg.contains("ssh-keygen"),
                    "expected ssh-keygen hint in: {msg}"
                );
            }
            other => panic!("expected InputParameters, got {other:?}"),
        }
    }

    #[test]
    fn test_unrecognized_format_returns_error() {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(b"this is not a key\n").expect("write");

        let err = load_rsa_key(f.path()).expect_err("should fail");
        assert!(
            matches!(err, OpenStackCliError::InputParameters(_)),
            "expected InputParameters, got {err:?}"
        );
    }

    #[test]
    fn test_missing_file_returns_io_error() {
        let err = load_rsa_key(Path::new("/nonexistent/key.pem")).expect_err("should fail");
        assert!(
            matches!(err, OpenStackCliError::IO { .. }),
            "expected IO error, got {err:?}"
        );
    }
}
