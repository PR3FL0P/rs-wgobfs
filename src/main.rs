use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self};

use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::runtime::Runtime;

use bytes::BytesMut;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use toml;

mod chacha;
mod chacha_glue;
mod guts;
mod wgobfs;

use crate::wgobfs::MAX_RND_LEN;
use crate::wgobfs::{obfs_udp_payload, unobfs_udp_payload, ForwardState};
use serde::Deserialize;
#[derive(Copy, Clone, Debug, Deserialize)]
enum OPMode {
    Obfs,
    UnObfs,
}
#[derive(Clone, Copy, Deserialize, Debug)]
struct AppArgs {
    local_addr: SocketAddr,
    fwd_addr: SocketAddr,
    key: [u8; 32],
    obfs_mode: OPMode,
}
#[derive(Deserialize)]
struct Peer {
    local_addr: String,
    fwd_addr: String,
    key: String,
}
#[derive(Deserialize)]
struct Config {
    obfs: Option<Peer>,
    unobfs: Option<Peer>,
}
fn parse_socket_addr(s: &str, prefer_v6: bool) -> Option<SocketAddr> {
    // without DNS
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr);
    }
    // use DNS
    let mut v4: Option<SocketAddr> = None;
    let mut v6: Option<SocketAddr> = None;
    let addrs = s.to_socket_addrs().ok()?;
    for addr in addrs {
        match addr {
            SocketAddr::V4(_) if v4.is_none() => v4 = Some(addr),
            SocketAddr::V6(_) if v6.is_none() => v6 = Some(addr),
            _ => {}
        }
    }

    if prefer_v6 && v6.is_some() {
        return v6;
    } else if v4.is_some() {
        return v4;
    } else if v6.is_some() {
        return v6;
    } else {
        return None;
    }
}

async fn create_dual_stack_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    // create a raw socket2 Socket
    let socket: Socket;
    if addr.is_ipv4() {
        socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    } else {
        socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        // disable "IPv6 Only" to allow IPv4 traffic on the same socket
        socket.set_only_v6(false)?;
    }

    // Increase socket buffer to 1MB
    // Default sizes in Windows/Linux/BSDs are not big enough on Gigabit
    // network. There are many retries when testing the tunnel with iperf3.
    //
    // OpenBSD 7.8 defaults:
    //   net.inet.udp.recvspace=41600
    //   net.inet.udp.sendspace=9216
    socket.set_recv_buffer_size(1024 * 1024)?;
    socket.set_send_buffer_size(1024 * 1024)?;

    socket.bind(&addr.into())?;
    // convert to Tokio UdpSocket
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

fn repeat_string_to_bytes(s: &str, len: usize) -> Vec<u8> {
    let v = s.as_bytes().to_vec();
    let repeat_count = (len + v.len() - 1) / v.len();
    let repeated = v.repeat(repeat_count);
    repeated.into_iter().take(len).collect()
}

struct Client {
    socket: Arc<UdpSocket>,
    handle: JoinHandle<()>,
    last_seen: AtomicU64,
}

impl Drop for Client {
    fn drop(&mut self) {
        // tell the spawned task to stop
        self.handle.abort();
    }
}

type ClientMap = Arc<RwLock<HashMap<SocketAddr, Client>>>;

struct ClientWorker {
    listen_socket: Arc<UdpSocket>,
    recv_socket: Arc<UdpSocket>,
}

impl ClientWorker {
    async fn run(self, client_addr: SocketAddr, key: [u8; 32], obfs_mode: OPMode) {
        let mut buf = [0u8; 1500];
        loop {
            let n = self.recv_socket.recv(&mut buf).await.unwrap();
            // unobfs and forward response back to the original client
            let mut rnd_len: usize = 0;
            match obfs_mode {
                OPMode::Obfs => {
                    if let ForwardState::XTContinue =
                        unobfs_udp_payload(&mut buf, n, &key, &mut rnd_len)
                    {
                        let _ = self
                            .listen_socket
                            .send_to(&buf[..n - rnd_len], client_addr)
                            .await;
                    }
                }

                OPMode::UnObfs => {
                    if let ForwardState::XTContinue =
                        obfs_udp_payload(&mut buf, n, &key, &mut rnd_len)
                    {
                        let _ = self
                            .listen_socket
                            .send_to(&buf[..n + rnd_len], client_addr)
                            .await;
                    }
                }
            }
        }
    }
}

struct ForwardWorker {
    fwd_socket: Arc<UdpSocket>,
}

impl ForwardWorker {
    async fn run(
        self,
        mut buf: BytesMut,
        len: usize,
        key: [u8; 32],
        obfs_mode: OPMode,
    ) -> std::io::Result<()> {
        let mut rnd_len: usize = 0;
        match obfs_mode {
            OPMode::Obfs => {
                if let ForwardState::XTContinue =
                    obfs_udp_payload(&mut buf, len, &key, &mut rnd_len)
                {
                    self.fwd_socket.send(&buf[..len + rnd_len]).await?;
                }
            }
            OPMode::UnObfs => {
                if let ForwardState::XTContinue =
                    unobfs_udp_payload(&mut buf, len, &key, &mut rnd_len)
                {
                    self.fwd_socket.send(&buf[..len - rnd_len]).await?;
                }
            }
        }

        Ok(())
    }
}

#[inline]
fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn clean_inactive_client(registry: ClientMap, timeout: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(120));
    loop {
        interval.tick().await;
        let mut map_write = registry.write().expect("Write-lock failed");
        // retain() removes items where the closure returns false
        map_write.retain(|addr, client| {
            let last_seen = client.last_seen.load(Ordering::Relaxed);
            let is_alive = (epoch_now() - last_seen) < timeout;
            if !is_alive {
                println!("Removing inactive client: {}", addr);
                client.handle.abort();
            }
            is_alive
        });
    }
}

const SLAB_SIZE: usize = 1024 * 256;

// Use single thread.
//
// - Multi thread works poorly on openbsd, async socket stops working after
//   sending at high speed for few seconds.
//
// - On Linux, single thread has higher throughput, likely due to better cache
//   locality. With a 7th gen i7, one thread is fast enough to almost saturate
//   Gigabit network.
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let config = std::fs::read_to_string("config.toml")?;

    let t1 = instanse_spawner(config.clone(), None, OPMode::Obfs);
    let duration = std::time::Duration::from_millis(100);
    let t2 = instanse_spawner(config, Some(duration), OPMode::UnObfs);

    t1.join().unwrap();
    t2.join().unwrap();
    Ok(())
}

fn instanse_spawner(
    s: String,
    t: Option<std::time::Duration>,
    mode: OPMode,
) -> std::thread::JoinHandle<()> {
    t.map(|d| thread::sleep(d));
    thread::spawn(move || {
        let args = match parse_args(&s, mode) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("Error: {}.", e);
                std::process::exit(1);
            }
        };
        let rt = Runtime::new().unwrap();
        let _ = rt.block_on(async {
            let listener = Arc::new(create_dual_stack_socket(args.local_addr).await?);
            run_instanse(args, listener).await.expect("penis");
            Ok::<(), std::io::Error>(())
        });
    })
}

async fn run_instanse(args: AppArgs, listener: Arc<UdpSocket>) -> std::io::Result<()> {
    println!("rs-wgobfs, a companion to the Linux kernel module xt_wgobfs");
    println!("  Listening on {}", args.local_addr);
    println!(
        "  Obfuscating and forwarding wireguard to {}",
        args.fwd_addr
    );

    let mut global_buf = BytesMut::with_capacity(SLAB_SIZE);
    unsafe {
        global_buf.set_len(SLAB_SIZE);
    }

    let client_map: ClientMap = Arc::new(RwLock::new(HashMap::new()));

    let timeout: u64 = 600;
    tokio::spawn(clean_inactive_client(Arc::clone(&client_map), timeout));
    loop {
        if global_buf.len() < 2048 {
            global_buf = BytesMut::with_capacity(SLAB_SIZE);
            unsafe {
                global_buf.set_len(SLAB_SIZE);
            }
        }

        let (len, client_addr) = listener.recv_from(&mut global_buf).await?;
        // only split_to multiple of 256
        let aligned_len = (len + MAX_RND_LEN + 255) & !255;
        let buf = global_buf.split_to(aligned_len);

        // read lock only lives inside scope
        let mut fwd_socket = {
            let map_read = client_map.read().expect("Read-lock failed");
            match map_read.get(&client_addr) {
                Some(client) => {
                    client.last_seen.store(epoch_now(), Ordering::Relaxed);
                    Some(client.socket.clone())
                }
                None => None,
            }
        };

        // write lock only lives inside scope
        if fwd_socket.is_none() {
            // create a dedicated socket to WG peer for the new client
            let bind_addr = match args.fwd_addr {
                SocketAddr::V4(_) => "0.0.0.0:0",
                SocketAddr::V6(_) => "[::]:0",
            };
            let s = Arc::new(UdpSocket::bind(bind_addr).await?);
            s.connect(args.fwd_addr).await?;
            println!("Accepting client {}", client_addr);
            // listen for return traffic from the server to THIS client
            let client_worker = ClientWorker {
                recv_socket: s.clone(),
                listen_socket: listener.clone(),
            };

            // use handle to abort inactive clients
            let handle = tokio::spawn(client_worker.run(client_addr, args.key, args.obfs_mode));

            let client = Client {
                socket: s.clone(),
                handle: handle,
                last_seen: AtomicU64::new(epoch_now()), // for cleanup
            };

            let mut map_write = client_map.write().expect("Write-lock failed");
            map_write.insert(client_addr, client);
            fwd_socket = Some(s);
        };

        let fwd_worker = ForwardWorker {
            fwd_socket: fwd_socket.unwrap(),
        };
        tokio::spawn(fwd_worker.run(buf, len, args.key, args.obfs_mode));
    }
}

fn parse_args(s: &str, mode: OPMode) -> Result<AppArgs, pico_args::Error> {
    let cfg: Config = toml::from_str(&s).expect("error parse config.toml");

    let cfg = if matches!(mode, OPMode::Obfs) {
        cfg.obfs.or(cfg.unobfs)
    } else {
        cfg.unobfs.or(cfg.obfs)
    }
    .ok_or(pico_args::Error::MissingArgument)?;

    let key32 = repeat_string_to_bytes(&cfg.key, 32);
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key32);

    let args = AppArgs {
        local_addr: parse_socket_addr(&cfg.local_addr, false)
            .expect("Failed to parse listening address"),
        fwd_addr: parse_socket_addr(&cfg.fwd_addr, false)
            .expect("Failed to parse the remote address"),
        key: key_arr,
        obfs_mode: mode,
    };

    Ok(args)
}
