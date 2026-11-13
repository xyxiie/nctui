//! Minimal Minecraft Java Edition server list ping (protocol 1.7+).

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Whether joining requires a Mojang/Microsoft account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnlineMode {
    /// `online-mode=true`: only authenticated (premium) accounts can join.
    Online,
    /// `online-mode=false`: cracked clients can join.
    Offline,
    /// The login handshake did not reveal the mode.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub version: String,
    pub online: u64,
    pub max: u64,
    pub motd: String,
    pub latency_ms: u128,
    pub online_mode: OnlineMode,
}

#[derive(Debug, Clone)]
pub struct ProbeError(pub String);

/// Queries the server list status of one host and port.
pub fn status(host: &str, port: u16) -> Result<Status, ProbeError> {
    let mut stream = connect(host, port)?;

    let started = Instant::now();
    stream
        .write_all(&handshake(host, port))
        .and_then(|_| stream.write_all(&status_request()))
        .map_err(|err| ProbeError(io_message(&err)))?;

    let json = read_status(&mut stream).map_err(|err| ProbeError(io_message(&err)))?;
    let latency_ms = started.elapsed().as_millis();

    let value: Value = serde_json::from_slice(&json)
        .map_err(|_| ProbeError("not a Minecraft status response".to_string()))?;

    Ok(Status {
        version: value
            .pointer("/version/name")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string(),
        online: value
            .pointer("/players/online")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        max: value
            .pointer("/players/max")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        motd: clean_motd(
            &value
                .get("description")
                .map(description_text)
                .unwrap_or_default(),
        ),
        latency_ms,
        online_mode: online_mode(host, port).unwrap_or(OnlineMode::Unknown),
    })
}

fn connect(host: &str, port: u16) -> Result<TcpStream, ProbeError> {
    let socket_addr = (host, port)
        .to_socket_addrs()
        .map_err(|err| ProbeError(format!("resolve failed: {err}")))?
        .next()
        .ok_or_else(|| ProbeError("could not resolve host".to_string()))?;

    let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3))
        .map_err(|err| ProbeError(io_message(&err)))?;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    Ok(stream)
}

/// Detects whether the server requires Mojang authentication.
///
/// The server list ping does not report `online-mode`, so this opens a second
/// connection and starts a login. An online-mode server replies with an
/// Encryption Request, an offline-mode server replies with Login Success (or
/// Set Compression first) because no authentication is performed.
///
/// The probe never authenticates and disconnects right after the first reply, so
/// the username may briefly show up in the server's log.
pub fn online_mode(host: &str, port: u16) -> Result<OnlineMode, ProbeError> {
    let mut stream = connect(host, port)?;
    stream
        .write_all(&login_request(host, port))
        .map_err(|err| ProbeError(io_message(&err)))?;

    let length = read_varint(&mut stream).map_err(|err| ProbeError(io_message(&err)))?;
    if !(1..=1_048_576).contains(&length) {
        return Ok(OnlineMode::Unknown);
    }
    let mut packet = vec![0u8; length as usize];
    stream
        .read_exact(&mut packet)
        .map_err(|err| ProbeError(io_message(&err)))?;

    let mut cursor = io::Cursor::new(packet);
    let packet_id = read_varint(&mut cursor).map_err(|err| ProbeError(io_message(&err)))?;
    Ok(match packet_id {
        PACKET_ENCRYPTION_REQUEST => OnlineMode::Online,
        // Compression is enabled for authenticated players on online-mode
        // servers, which only happens after an Encryption Request.
        PACKET_LOGIN_SUCCESS | PACKET_SET_COMPRESSION => OnlineMode::Offline,
        // A disconnect (whitelist, full, bad name) says nothing about the mode.
        _ => OnlineMode::Unknown,
    })
}

fn io_message(err: &io::Error) -> String {
    match err.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "timed out".to_string(),
        io::ErrorKind::ConnectionRefused => "connection refused".to_string(),
        io::ErrorKind::ConnectionReset => "connection reset".to_string(),
        _ => err.to_string(),
    }
}

const PROBE_NAME: &str = "MCScan";
const PACKET_LOGIN_SUCCESS: i32 = 0x02;
const PACKET_ENCRYPTION_REQUEST: i32 = 0x01;
const PACKET_SET_COMPRESSION: i32 = 0x03;

/// A syntactically valid version 4 UUID for the probe login.
const PROBE_UUID: [u8; 16] = [
    0x6d, 0x63, 0x73, 0x63, 0x61, 0x6e, 0x40, 0x6d, 0x80, 0x73, 0x63, 0x61, 0x6e, 0x00, 0x00,
    0x01,
];

fn handshake(host: &str, port: u16) -> Vec<u8> {
    let mut body = Vec::new();
    write_varint(&mut body, 0); // packet id: handshake
    write_varint(&mut body, -1); // protocol version: any
    write_string(&mut body, host);
    body.extend_from_slice(&port.to_be_bytes());
    write_varint(&mut body, 1); // next state: status
    framed(body)
}

fn status_request() -> Vec<u8> {
    framed(vec![0])
}

/// A handshake asking for the login state plus a Login Start packet.
fn login_request(host: &str, port: u16) -> Vec<u8> {
    let mut body = Vec::new();
    write_varint(&mut body, 0); // packet id: handshake
    write_varint(&mut body, -1); // protocol version: any
    write_string(&mut body, host);
    body.extend_from_slice(&port.to_be_bytes());
    write_varint(&mut body, 2); // next state: login
    let mut request = framed(body);

    // Login Start carries the name and a UUID; older servers ignore the extras.
    let mut body = Vec::new();
    write_varint(&mut body, 0); // packet id: login start
    write_string(&mut body, PROBE_NAME);
    body.push(1); // client supplied a UUID
    body.extend_from_slice(&PROBE_UUID);
    request.extend_from_slice(&framed(body));
    request
}

fn framed(body: Vec<u8>) -> Vec<u8> {
    let mut packet = Vec::with_capacity(body.len() + 5);
    write_varint(&mut packet, body.len() as i32);
    packet.extend_from_slice(&body);
    packet
}

fn write_string(buffer: &mut Vec<u8>, value: &str) {
    write_varint(buffer, value.len() as i32);
    buffer.extend_from_slice(value.as_bytes());
}

fn write_varint(buffer: &mut Vec<u8>, value: i32) {
    let mut value = value as u32;
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buffer.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn read_varint<R: Read>(reader: &mut R) -> io::Result<i32> {
    let mut value: u32 = 0;
    for shift in [0u32, 7, 14, 21, 28] {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        value |= u32::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(value as i32);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "varint is too long",
    ))
}

fn read_status<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let length = read_varint(reader)?;
    if !(0..=2_097_152).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid status packet length",
        ));
    }

    let mut packet = vec![0u8; length as usize];
    reader.read_exact(&mut packet)?;

    let mut cursor = io::Cursor::new(packet);
    let packet_id = read_varint(&mut cursor)?;
    if packet_id != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected packet id",
        ));
    }

    let json_length = read_varint(&mut cursor)?;
    if json_length < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "negative JSON length",
        ));
    }

    let start = cursor.position() as usize;
    let packet = cursor.into_inner();
    let end = start + json_length as usize;
    if end > packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated status response",
        ));
    }

    Ok(packet[start..end].to_vec())
}

fn description_text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(items) => items.iter().map(description_text).collect(),
        Value::Object(map) => {
            let mut text = String::new();
            if let Some(part) = map.get("text") {
                text.push_str(&description_text(part));
            }
            if let Some(extra) = map.get("extra") {
                text.push_str(&description_text(extra));
            }
            text
        }
        _ => String::new(),
    }
}

/// Drops legacy formatting codes (§a, §l, …) and flattens line breaks.
fn clean_motd(text: &str) -> String {
    let mut stripped = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '§' {
            chars.next();
        } else {
            stripped.push(c);
        }
    }
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn serve_once(json: &'static str) -> (String, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = socket.try_clone().unwrap();
            read_packet(&mut reader);
            read_packet(&mut reader);

            let mut body = Vec::new();
            write_varint(&mut body, 0);
            write_string(&mut body, json);
            let mut response = Vec::new();
            write_varint(&mut response, body.len() as i32);
            response.extend_from_slice(&body);
            socket.write_all(&response).unwrap();
        });
        (address.ip().to_string(), address.port())
    }

    fn read_packet<R: Read>(reader: &mut R) -> Vec<u8> {
        let length = read_varint(reader).unwrap();
        let mut packet = vec![0u8; length as usize];
        reader.read_exact(&mut packet).unwrap();
        packet
    }

    /// Accepts a login handshake and replies with a single packet id.
    fn serve_login_reply(packet_id: i32) -> (String, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut reader = socket.try_clone().unwrap();
            read_packet(&mut reader);
            let start = read_packet(&mut reader);
            assert_eq!(&start[start.len() - 17..start.len() - 16], &[1]);

            let mut body = Vec::new();
            write_varint(&mut body, packet_id);
            let mut response = Vec::new();
            write_varint(&mut response, body.len() as i32);
            response.extend_from_slice(&body);
            socket.write_all(&response).unwrap();
        });
        (address.ip().to_string(), address.port())
    }

    #[test]
    fn reads_status_json() {
        let (host, port) = serve_once(
            r#"{"version":{"name":"1.20.4"},"players":{"online":2,"max":20},"description":{"text":"Hello §a","extra":[{"text":"world"}]}}"#,
        );
        let status = status(&host, port).unwrap();
        assert_eq!(status.version, "1.20.4");
        assert_eq!(status.online, 2);
        assert_eq!(status.max, 20);
        assert_eq!(status.motd, "Hello world");
    }

    #[test]
    fn detects_online_mode_from_encryption_request() {
        let (host, port) = serve_login_reply(PACKET_ENCRYPTION_REQUEST);
        assert_eq!(online_mode(&host, port).unwrap(), OnlineMode::Online);
    }

    #[test]
    fn detects_offline_mode_from_login_success() {
        let (host, port) = serve_login_reply(PACKET_LOGIN_SUCCESS);
        assert_eq!(online_mode(&host, port).unwrap(), OnlineMode::Offline);
    }

    #[test]
    fn treats_disconnect_as_unknown_mode() {
        let (host, port) = serve_login_reply(0x00);
        assert_eq!(online_mode(&host, port).unwrap(), OnlineMode::Unknown);
    }

    #[test]
    fn rejects_non_minecraft_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 512];
            let _ = socket.read(&mut request);
            socket.write_all(&[0x03, 0x00, 0x01, 0x00]).unwrap();
        });
        let error = status(&address.ip().to_string(), address.port()).unwrap_err();
        assert!(!error.0.is_empty());
    }

    #[test]
    fn varint_round_trip() {
        for value in [0, 1, 127, 128, 25565, 2_097_151, -1] {
            let mut buffer = Vec::new();
            write_varint(&mut buffer, value);
            let mut cursor = io::Cursor::new(buffer);
            assert_eq!(read_varint(&mut cursor).unwrap(), value);
        }
    }
}
