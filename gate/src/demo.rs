//! The public console has to be able to make `oldworker` genuinely stop
//! answering, otherwise the drift it demonstrates would be theatre. This is the
//! only place the gate reaches out to another service, and it only ever talks
//! to the decommission target.

use std::io::{Error, ErrorKind};
use std::sync::OnceLock;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Long enough for three 15 s probe cycles plus slack; oldworker caps it too.
pub const PLAYDEAD_SECONDS: u32 = 90;

static HOST: OnceLock<String> = OnceLock::new();
static PORT: OnceLock<u16> = OnceLock::new();

/// Overridable so the scenario can be exercised outside Zerops, where the
/// service hostnames do not resolve. Defaults are the real ones.
pub fn target() -> &'static str {
    HOST.get_or_init(|| std::env::var("DEMO_TARGET").unwrap_or_else(|_| "oldworker".to_string()))
}

pub fn target_port() -> u16 {
    *PORT.get_or_init(|| {
        std::env::var("DEMO_TARGET_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(3000)
    })
}

fn timed_out(what: &'static str) -> Error {
    Error::new(ErrorKind::TimedOut, what)
}

/// Minimal HTTP/1.1 POST. Internal traffic is plain HTTP over the project's
/// private network, and this is one fixed request to one fixed host — a full
/// client crate would be a lot of dependency for that.
pub async fn play_dead(seconds: u32) -> std::io::Result<()> {
    let body = format!("{{\"seconds\":{seconds}}}");
    let request = format!(
        "POST /playdead HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        target(),
        body.len()
    );

    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect((target(), target_port())),
    )
    .await
    .map_err(|_| timed_out("connecting to the decommission target timed out"))??;

    stream.write_all(request.as_bytes()).await?;

    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .map_err(|_| timed_out("the decommission target did not reply"))??;

    if buf[..n].starts_with(b"HTTP/1.1 200") {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Other, "decommission target refused"))
    }
}
