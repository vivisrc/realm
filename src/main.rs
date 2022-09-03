use std::{io, sync::Arc};

use chrono::{
    format::{Fixed, Item, Numeric, Pad},
    Local,
};
use colored::Colorize;
use fern::Dispatch;
use futures::future;
use log::{Level, LevelFilter};

use crate::{
    context::ServerContext,
    server::{TcpDnsServer, UdpDnsServer},
};

pub mod bitfield;
pub mod context;
pub mod message;
pub mod node;
pub mod opt;
pub mod question;
pub mod record;
pub mod resolver;
pub mod serial;
pub mod server;
pub mod text;
pub mod wire;
pub mod zone;

#[tokio::main]
async fn main() {
    let context = Arc::new(ServerContext::from_env());

    init_logger(context.config.log.level);

    let mut handles = Vec::new();

    if context.config.server.udp_enabled {
        let context = Arc::clone(&context);
        handles.push(tokio::spawn(async {
            UdpDnsServer::new(context).run().await.unwrap();
        }));
    }

    if context.config.server.tcp_enabled {
        let context = Arc::clone(&context);
        handles.push(tokio::spawn(async {
            TcpDnsServer::new(context).run().await.unwrap();
        }));
    }

    future::join_all(handles).await;
}

fn init_logger(filter: LevelFilter) {
    Dispatch::new()
        .format(|out, message, record| {
            let level = match record.level() {
                Level::Error => " ERR ".red().reversed(),
                Level::Warn => " WRN ".magenta().reversed(),
                Level::Info => " INF ".blue().reversed(),
                Level::Debug => " DBG ".green().reversed(),
                Level::Trace => " TRC ".reversed(),
            };

            out.finish(format_args!(
                "{} {} [{}] {}",
                level,
                Local::now()
                    .format_with_items(
                        [
                            Item::Numeric(Numeric::Hour, Pad::Zero),
                            Item::Literal(":"),
                            Item::Numeric(Numeric::Minute, Pad::Zero),
                            Item::Literal(":"),
                            Item::Numeric(Numeric::Second, Pad::Zero),
                            Item::Fixed(Fixed::Nanosecond3)
                        ]
                        .iter()
                    )
                    .to_string()
                    .dimmed(),
                record.target().bold(),
                message,
            ))
        })
        .level(filter)
        .level_for("mio::poll", LevelFilter::Warn)
        .chain(io::stderr())
        .apply()
        .unwrap()
}
