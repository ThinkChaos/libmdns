#[macro_use(quick_error)]
extern crate quick_error;

#[macro_use]
extern crate log;

extern crate byteorder;
extern crate futures;
extern crate libc;
extern crate multimap;
extern crate net2;
extern crate nix;
extern crate rand;
extern crate tokio;
extern crate tokio_reactor;
extern crate tokio_udp;

use futures::sync::mpsc;
use futures::{future, Future};
#[cfg(not(windows))]
use net2::unix::UnixUdpBuilderExt;
use net2::UdpBuilder;
use std::cell::RefCell;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;

mod dns_parser;
use dns_parser::Name;

mod fsm;
#[cfg(windows)]
#[path = "netwin.rs"]
mod net;
#[cfg(not(windows))]
mod net;
mod services;

use fsm::{Command, FSM};
use net::gethostname;
use services::{ServiceData, Services};

const DEFAULT_TTL: u32 = 60;
const MDNS_PORT: u16 = 5353;

pub struct Builder {
    hostname: Option<String>,
    addrs: Vec<IpAddr>,
}

pub struct Responder {
    fsms: RefCell<Vec<FSM>>,
    services: Services,
    commands: RefCell<CommandSender>,
    shutdown: Arc<Shutdown>,
}

pub struct Service {
    id: usize,
    services: Services,
    commands: CommandSender,
    _shutdown: Arc<Shutdown>,
}

impl Builder {
    pub fn new() -> Builder {
        Builder {
            hostname: None,
            addrs: Vec::new(),
        }
    }

    pub fn hostname<S: Into<String>>(mut self, hostname: S) -> Builder {
        let mut hostname = hostname.into();

        if !hostname.ends_with(".local") {
            hostname.push_str(".local");
        }

        self.hostname = Some(hostname);
        self
    }

    pub fn add_addr(mut self, addr: IpAddr) -> Builder {
        self.addrs.push(addr.into());
        self
    }

    pub fn bind(self) -> io::Result<Responder> {
        // TODO: document this behavior
        let hostname = if let Some(hostname) = self.hostname {
            hostname
        } else {
            gethostname()?
        };

        // TODO: document this behavior
        let mut addrs = self.addrs;
        if addrs.is_empty() {
            debug!("Tried to bind Responder to 0 addrs. Binding to all interfaces.");
            addrs.push(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))); // 0.0.0.0
            addrs.push(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))); // ::
        }

        Responder::from_builder(hostname, addrs)
    }
}

impl Responder {
    #[deprecated(
        since = "0.3",
        note = "Builder API gives more control over configuration and runtime."
    )]
    pub fn new() -> io::Result<Responder> {
        let mut responder = Builder::new().bind()?;
        responder.start()?;
        Ok(responder)
    }

    fn from_builder(hostname: String, addrs: Vec<IpAddr>) -> io::Result<Responder> {
        if addrs.is_empty() {
            panic!("Responder::new called with `addrs == vec![]`");
        }

        let services = Services::new(hostname);

        let sockets = Self::bind(addrs)?;

        let (fsms, commands): (Vec<_>, Vec<_>) = sockets
            .into_iter()
            .map(|socket| {
                let socket =
                    tokio_udp::UdpSocket::from_std(socket, &tokio_reactor::Handle::default())
                        .expect("tokio::net::UdpSocket::from_std failed");

                FSM::new(socket, &services)
            }).unzip();

        let commands = CommandSender(commands);
        let shutdown = Arc::new(Shutdown(commands.clone()));

        Ok(Responder {
            fsms: RefCell::new(fsms),
            services,
            commands: RefCell::new(commands),
            shutdown,
        })
    }

    fn bind(addrs: Vec<IpAddr>) -> io::Result<Vec<UdpSocket>> {
        let mut sockets = Vec::with_capacity(addrs.len());

        for addr in addrs {
            let builder = if addr.is_ipv4() {
                UdpBuilder::new_v4()?
            } else {
                UdpBuilder::new_v6()?
            };

            builder.reuse_address(true)?;
            #[cfg(not(windows))]
            builder.reuse_port(true)?;

            let socket = builder.bind(&SocketAddr::new(addr, MDNS_PORT))?;

            if addr.is_ipv4() {
                socket.join_multicast_v4(
                    &Ipv4Addr::new(224, 0, 0, 251),
                    &Ipv4Addr::new(0, 0, 0, 0),
                )?;
            } else {
                socket.join_multicast_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 0)?;
            }

            sockets.push(socket);
        }

        Ok(sockets)
    }

    pub fn serve(&self) -> impl Future<Item = (), Error = io::Error> {
        // Check if Responder was already started
        if self.fsms.borrow().is_empty() {
            panic!("`Responder::serve` was called twice.");
        }

        let fsms = self.fsms.replace(vec![]);

        future::join_all(fsms).map(|_| ())
    }

    pub fn start(&mut self) -> io::Result<thread::JoinHandle<()>> {
        let future = self.serve();

        thread::Builder::new()
            .name("mdns-responder".to_owned())
            .spawn(move || {
                tokio::run(future.map_err(|e| {
                    warn!("mdns error {:?}", e);
                    ()
                }));
            })
    }

    pub fn register(&self, svc_type: String, svc_name: String, port: u16, txt: &[&str]) -> Service {
        let txt = if txt.is_empty() {
            vec![0]
        } else {
            txt.into_iter()
                .flat_map(|entry| {
                    let entry = entry.as_bytes();
                    if entry.len() > 255 {
                        panic!("{:?} is too long for a TXT record", entry);
                    }
                    std::iter::once(entry.len() as u8).chain(entry.into_iter().cloned())
                }).collect()
        };

        let svc = ServiceData {
            typ: Name::from_str(format!("{}.local", svc_type)).unwrap(),
            name: Name::from_str(format!("{}.{}.local", svc_name, svc_type)).unwrap(),
            port: port,
            txt: txt,
        };

        self.commands
            .borrow_mut()
            .send_unsolicited(svc.clone(), DEFAULT_TTL, true);

        let id = self.services.register(svc);

        Service {
            id: id,
            commands: self.commands.borrow().clone(),
            services: self.services.clone(),
            _shutdown: self.shutdown.clone(),
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let svc = self.services.unregister(self.id);
        self.commands.send_unsolicited(svc, 0, false);
    }
}

struct Shutdown(CommandSender);
impl Drop for Shutdown {
    fn drop(&mut self) {
        self.0.send_shutdown();
        // TODO wait for tasks to shutdown
    }
}

#[derive(Clone)]
struct CommandSender(Vec<mpsc::UnboundedSender<Command>>);
impl CommandSender {
    fn send(&mut self, cmd: Command) {
        for tx in self.0.iter_mut() {
            tx.unbounded_send(cmd.clone()).expect("responder died");
        }
    }

    fn send_unsolicited(&mut self, svc: ServiceData, ttl: u32, include_ip: bool) {
        self.send(Command::SendUnsolicited {
            svc: svc,
            ttl: ttl,
            include_ip: include_ip,
        });
    }

    fn send_shutdown(&mut self) {
        self.send(Command::Shutdown);
    }
}
