//! A Redis Streams stand-in: answers the commands a Redis client sends on connect and records
//! every entry added with `XADD`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// One entry added to a stream: its stream name and field-value pairs, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEntry {
    pub stream: String,
    pub fields: Vec<(String, String)>,
}

impl StreamEntry {
    pub fn field(
        &self,
        name: &str,
    ) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }
}

pub struct RedisStreamStandIn {
    port: u16,
    entries: Arc<Mutex<Vec<StreamEntry>>>,
    handle: JoinHandle<()>,
}

impl std::fmt::Debug for RedisStreamStandIn {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("RedisStreamStandIn")
            .field("port", &self.port)
            .finish()
    }
}

impl Drop for RedisStreamStandIn {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl RedisStreamStandIn {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the Redis stand-in");
        let port = listener
            .local_addr()
            .expect("Redis stand-in address")
            .port();
        let entries = Arc::new(Mutex::new(Vec::new()));
        let recorded = entries.clone();
        let handle = tokio::spawn(async move {
            while let Ok((connection, _)) = listener.accept().await {
                tokio::spawn(serve(connection, recorded.clone()));
            }
        });
        Self { port, entries, handle }
    }

    pub fn url(&self) -> String {
        format!("redis://127.0.0.1:{}", self.port)
    }

    pub fn entries(&self) -> Vec<StreamEntry> {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The first entry that satisfies `matches`, waiting up to `timeout` for it to arrive.
    pub async fn wait_for(
        &self,
        timeout: Duration,
        matches: impl Fn(&StreamEntry) -> bool,
    ) -> Option<StreamEntry> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(entry) = self
                .entries()
                .into_iter()
                .find(&matches)
            {
                return Some(entry);
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

async fn serve(
    connection: TcpStream,
    entries: Arc<Mutex<Vec<StreamEntry>>>,
) {
    let (read, mut write) = connection.into_split();
    let mut reader = BufReader::new(read);
    while let Some(command) = read_command(&mut reader).await {
        let reply = match command
            .first()
            .map(|name| name.to_ascii_uppercase())
            .as_deref()
        {
            Some("XADD") if command.len() >= 5 && command.len() % 2 == 1 => {
                let mut recorded = entries
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                recorded.push(StreamEntry {
                    stream: command[1].clone(),
                    fields: command[3..]
                        .chunks(2)
                        .map(|pair| (pair[0].clone(), pair[1].clone()))
                        .collect(),
                });
                let id = format!("{}-0", recorded.len());
                format!("${}\r\n{id}\r\n", id.len())
            }
            Some("XADD") => "-ERR wrong number of arguments for 'xadd' command\r\n".to_string(),
            Some("PING") => "+PONG\r\n".to_string(),
            _ => "+OK\r\n".to_string(),
        };
        if write
            .write_all(reply.as_bytes())
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Reads one command, an array of bulk strings, or `None` once the client is gone or sends
/// something else.
async fn read_command<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> Option<Vec<String>> {
    let count: usize = read_header(reader, '*').await?;
    let mut arguments = Vec::with_capacity(count);
    for _ in 0..count {
        let length: usize = read_header(reader, '$').await?;
        let mut bytes = vec![0; length + 2];
        reader
            .read_exact(&mut bytes)
            .await
            .ok()?;
        bytes.truncate(length);
        arguments.push(String::from_utf8(bytes).ok()?);
    }
    Some(arguments)
}

async fn read_header<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    marker: char,
) -> Option<usize> {
    let mut line = String::new();
    if reader
        .read_line(&mut line)
        .await
        .ok()?
        == 0
    {
        return None;
    }
    line.trim_end()
        .strip_prefix(marker)?
        .parse()
        .ok()
}
