use std::{
    collections::{HashMap, HashSet},
    env,
    fs::File,
    io::Read,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::prelude::OsStringExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use log::LevelFilter;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use serde_default::DefaultFromSerde;
use serde_with::{hex::Hex, serde_as, BytesOrString, DurationSecondsWithFrac};

use crate::{node::Node, question::Question, zone::read_zone};

const fn default_true() -> bool {
    true
}

fn default_bind_addr() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 53))
}

const fn default_max_payload_size() -> u16 {
    1232
}

#[cfg(debug_assertions)]
const fn default_log_level() -> LevelFilter {
    LevelFilter::Trace
}

#[cfg(not(debug_assertions))]
const fn default_log_level() -> LevelFilter {
    LevelFilter::Info
}

fn default_secret() -> [u8; 16] {
    let mut secret = [0; 16];
    ChaCha20Rng::from_entropy().fill_bytes(&mut secret);
    secret
}

fn default_identity() -> Vec<u8> {
    gethostname::gethostname().into_vec()
}

const fn default_keepalive() -> Duration {
    Duration::from_secs(300)
}

#[derive(Deserialize, DefaultFromSerde)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    #[serde(default = "default_log_level", with = "LevelFilterDef")]
    pub level: LevelFilter,
}

#[derive(Deserialize)]
#[serde(remote = "LevelFilter", rename_all = "kebab-case")]
pub enum LevelFilterDef {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[serde_as]
#[derive(Deserialize, DefaultFromSerde)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_true")]
    pub udp_enabled: bool,
    #[serde(default = "default_bind_addr")]
    pub udp_bind_addr: SocketAddr,
    #[serde(default = "default_max_payload_size")]
    pub udp_max_payload_size: u16,

    #[serde(default = "default_true")]
    pub tcp_enabled: bool,
    #[serde(default = "default_bind_addr")]
    pub tcp_bind_addr: SocketAddr,

    #[serde(default = "default_true")]
    pub cookie_enabled: bool,
    #[serde(default = "default_secret")]
    #[serde_as(as = "Hex")]
    pub cookie_secret: [u8; 16],
    #[serde(default)]
    pub cookie_strategy: CookieStrategy,

    #[serde(default = "default_true")]
    pub identity_enabled: bool,
    #[serde_as(as = "BytesOrString")]
    #[serde(default = "default_identity")]
    pub identity_name: Vec<u8>,

    #[serde_as(deserialize_as = "DurationSecondsWithFrac<f64>")]
    #[serde(default = "default_keepalive")]
    pub keepalive: Duration,
}

#[derive(Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CookieStrategy {
    #[default]
    Off,
    Validate,
    Enforce,
}

#[serde_as]
#[derive(Deserialize, DefaultFromSerde)]
#[serde(deny_unknown_fields)]
pub struct ZoneConfig {
    #[serde(default)]
    pub file: Option<PathBuf>,
}

#[derive(Deserialize, DefaultFromSerde)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub zones: HashMap<String, ZoneConfig>,
}

pub struct ServerContext {
    pub config: Arc<Config>,
    pub root: Node,
}

impl ServerContext {
    pub fn from_env() -> Self {
        let config_path = env::var("CONFIG_FILE").unwrap_or_else(|_| "realm.yml".to_string());
        let config_path = Path::new(config_path.as_str());

        let config_file = File::open(config_path).unwrap_or_else(|err| {
            eprintln!("Couldn't open config file at {:?}", config_path);
            eprintln!("Tip: use the CONFIG_FILE environment variable to specify a file location.");
            panic!("{}", err);
        });
        let config = serde_yaml::from_reader::<_, Config>(config_file)
            .unwrap_or_else(|err| panic!("Error parsing config: {}", err));

        let mut root = Node::new();

        for (name, zone) in &config.zones {
            let mut name = name.to_string();
            if !name.ends_with('.') {
                name.push('.')
            }

            let origin = name
                .parse()
                .unwrap_or_else(|_| panic!("{:?} is not a valid origin", name));

            let mut zone_file = zone
                .file
                .as_deref()
                .map(|path| {
                    File::open(path).unwrap_or_else(|err| {
                        eprintln!("Couldn't open zone file at {:?}", path);
                        panic!("{}", err);
                    })
                })
                .unwrap_or_else(|| {
                    let path = Path::new("zones").join(name + "zone");
                    File::open(&path).unwrap_or_else(|err| {
                        eprintln!("Couldn't open zone file at {:?}", path);
                        eprintln!("Tip: use the `file` directive to specify a file location.");
                        panic!("{}", err);
                    })
                });

            let mut zone_buf = String::with_capacity(zone_file.metadata().unwrap().len() as usize);
            zone_file
                .read_to_string(&mut zone_buf)
                .expect("Error reading zone");
            match read_zone(&zone_buf, origin) {
                Ok(zone) => root.merge(zone),
                Err(err) => panic!("Couldn't parse zone file: {:?}", err),
            }
        }

        Self {
            config: Arc::from(config),
            root,
        }
    }
}

pub struct ConnectionContext {
    pub config: Arc<Config>,
    pub server: Arc<ServerContext>,
    pub addr: SocketAddr,
    pub keepalive: Duration,
}

impl ConnectionContext {
    pub fn new(server: Arc<ServerContext>, addr: SocketAddr, keepalive: Duration) -> Self {
        Self {
            config: Arc::clone(&server.config),
            server,
            addr,
            keepalive,
        }
    }
}

pub struct QueryContext {
    pub config: Arc<Config>,
    pub server: Arc<ServerContext>,
    pub connection: Arc<Mutex<ConnectionContext>>,
    pub resolved: HashSet<Question>,
}

impl QueryContext {
    pub fn new(connection: Arc<Mutex<ConnectionContext>>) -> Self {
        let server = Arc::clone(&connection.lock().unwrap().server);
        Self {
            config: Arc::clone(&server.config),
            server,
            connection: Arc::clone(&connection),
            resolved: HashSet::new(),
        }
    }
}
