use std::{
    io::Write,
    sync::{
        OnceLock,
        mpsc::{SyncSender, sync_channel},
    },
};

use serde::Serialize;

use crate::ai::wire::AiCall;

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Line<'a> {
    Ready {
        port: u16,
        username: &'a str,
        password: &'a str,
        ca: &'a str,
        hosts: &'a [&'a str],
    },
    AiCall(&'a AiCall),
}

static WRITER: OnceLock<SyncSender<String>> = OnceLock::new();

/// Writes a JSON line to stdout from a dedicated thread, so a parent that stops
/// reading stdout can never stall request handling. Lines are dropped when the queue is full.
pub fn send(line: &Line) {
    let Ok(json) = serde_json::to_string(line) else {
        return;
    };
    let writer = WRITER.get_or_init(|| {
        let (sender, receiver) = sync_channel::<String>(1024);
        std::thread::spawn(move || {
            let mut stdout = std::io::stdout();
            for json in receiver {
                if writeln!(stdout, "{json}")
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    return;
                }
            }
        });
        sender
    });
    let _ = writer.try_send(json);
}
