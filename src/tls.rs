use std::{fs, io};
use std::path::{Path, PathBuf};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;

pub(crate) fn get_server_config(
    public_cert_path: PathBuf, private_key_path: PathBuf) -> ServerConfig {
    // TODO: Temporary, make proper TLS handler
    let public_cert = load_public_certificates(public_cert_path);
    let private_key = load_private_key(private_key_path);
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(public_cert, private_key)
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    // Return this
    server_config
}

fn load_pem_reader(file_path: PathBuf) -> io::BufReader<fs::File> {
    // TODO: Proper logger/error handler
    let pem_file = fs::File::open(file_path).unwrap();
    // Return BufReader
    io::BufReader::new(pem_file)
}

fn load_private_key<'a>(file_path: PathBuf) -> PrivateKeyDer<'a> {
    let mut reader = load_pem_reader(file_path);
    // Return private key
    // TODO: Proper logger/handler
    rustls_pemfile::private_key(&mut reader).map(|key| key.unwrap()).unwrap()
}

fn load_public_certificates<'a>(file_path: PathBuf) -> Vec<CertificateDer<'a>> {
    let mut reader = load_pem_reader(file_path);
    // Return private key
    // TODO: Proper logger/handler
    rustls_pemfile::certs(&mut reader).map(|cert| cert.unwrap()).collect()
}