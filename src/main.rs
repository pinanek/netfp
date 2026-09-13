#[cfg(feature = "jarm")]
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

#[cfg(feature = "jarm")]
use netfp::{
    Error, JarmFingerprint,
    tls::{ServerHelloDecoder, TlsRecord, TlsServerHello},
};

#[cfg(feature = "jarm")]
const TARGET: &str = "1.1.1.1";
#[cfg(feature = "jarm")]
const PORT: u16 = 443;
#[cfg(feature = "jarm")]
const TIMEOUT: Duration = Duration::from_secs(20);

#[cfg(feature = "jarm")]
fn scan_probe(
    address: SocketAddr,
    probe: &[u8],
) -> Result<Option<TlsServerHello>, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect_timeout(&address, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    stream.write_all(probe)?;

    let mut server_hello_decoder = ServerHelloDecoder::new();
    let mut receive_buffer = Vec::new();
    let mut read_buffer = [0u8; 4096];

    loop {
        let bytes_read = stream.read(&mut read_buffer)?;
        if bytes_read == 0 {
            return Ok(None);
        }
        receive_buffer.extend_from_slice(&read_buffer[..bytes_read]);

        let mut consumed_bytes = 0;
        while consumed_bytes < receive_buffer.len() {
            let (record, record_length) =
                match TlsRecord::try_from_bytes(&receive_buffer[consumed_bytes..]) {
                    Ok(record) => record,
                    Err(Error::UnexpectedEof { .. }) => break,
                    Err(error) => return Err(error.into()),
                };

            consumed_bytes += record_length;
            if let Some(server_hello) = server_hello_decoder.push_record(&record)? {
                return Ok(Some(server_hello));
            }
        }

        if consumed_bytes > 0 {
            receive_buffer.drain(..consumed_bytes);
        }
    }
}

#[cfg(feature = "jarm")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let address = SocketAddr::from(([1, 1, 1, 1], PORT));
    let fingerprint_builder = JarmFingerprint::new(TARGET);
    let mut server_hellos = Vec::new();

    for (probe_index, probe) in fingerprint_builder.probes()?.iter().enumerate() {
        let server_hello = match scan_probe(address, probe) {
            Ok(server_hello) => server_hello,
            Err(error) => {
                eprintln!("probe {} failed: {error}", probe_index + 1);
                None
            }
        };
        server_hellos.push(server_hello);
    }

    println!(
        "Rust JARM for {TARGET}:{PORT}: {}",
        fingerprint_builder.fingerprint(&server_hellos)
    );

    Ok(())
}

#[cfg(not(feature = "jarm"))]
fn main() {
    eprintln!("the `jarm` feature is required");
}
