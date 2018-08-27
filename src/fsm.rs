use dns_parser::{self, Name, QueryClass, QueryType, RRData};
use futures::sync::mpsc;
use futures::{Async, Future, Poll, Stream};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio_udp::UdpSocket;

use super::{DEFAULT_TTL, MDNS_PORT};
use net;
use services::{ServiceData, Services};

pub type AnswerBuilder = dns_parser::Builder<dns_parser::Answers>;

#[derive(Clone, Debug)]
pub enum Command {
    SendUnsolicited {
        svc: ServiceData,
        ttl: u32,
        include_ip: bool,
    },
    Shutdown,
}

pub struct FSM {
    socket: UdpSocket,
    is_ipv6: bool,
    services: Services,
    commands: mpsc::UnboundedReceiver<Command>,
    outgoing: VecDeque<(Vec<u8>, SocketAddr)>,
}

impl FSM {
    pub fn new(socket: UdpSocket, services: &Services) -> (FSM, mpsc::UnboundedSender<Command>) {
        let (tx, rx) = mpsc::unbounded();

        let is_ipv6 = socket
            .local_addr()
            .expect("Could not get socket's local address.")
            .is_ipv6();

        let fsm = FSM {
            socket: socket,
            is_ipv6: is_ipv6,
            services: services.clone(),
            commands: rx,
            outgoing: VecDeque::new(),
        };

        (fsm, tx)
    }

    fn recv_packets(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let (bytes, addr) = match self.socket.poll_recv_from(&mut buf) {
                Ok(Async::Ready((bytes, addr))) => (bytes, addr),
                Ok(Async::NotReady) => break,
                Err(err) => return Err(err),
            };

            if bytes >= buf.len() {
                warn!("buffer too small for packet from {:?}", addr);
                continue;
            }

            self.handle_packet(&buf[..bytes], addr);
        }
        Ok(())
    }

    fn handle_packet(&mut self, buffer: &[u8], addr: SocketAddr) {
        trace!("received packet from {:?}", addr);

        let packet = match dns_parser::Packet::parse(buffer) {
            Ok(packet) => packet,
            Err(error) => {
                warn!("couldn't parse packet from {:?}: {}", addr, error);
                return;
            }
        };

        if !packet.header.query {
            trace!("received packet from {:?} with no query", addr);
            return;
        }

        if packet.header.truncated {
            warn!("dropping truncated packet from {:?}", addr);
            return;
        }

        let mut unicast_builder = dns_parser::Builder::new_response(packet.header.id, false, true)
            .move_to::<dns_parser::Answers>();
        let mut multicast_builder =
            dns_parser::Builder::new_response(packet.header.id, false, true)
                .move_to::<dns_parser::Answers>();
        unicast_builder.set_max_size(None);
        multicast_builder.set_max_size(None);

        for question in packet.questions {
            if question.qclass == QueryClass::IN || question.qclass == QueryClass::Any {
                if question.qu {
                    unicast_builder = self.handle_question(&question, unicast_builder);
                } else {
                    multicast_builder = self.handle_question(&question, multicast_builder);
                }
            }
        }

        if !multicast_builder.is_empty() {
            let response = multicast_builder.build().unwrap_or_else(|x| x);
            let addr = SocketAddr::new(self.mdns_group(), MDNS_PORT);
            self.outgoing.push_back((response, addr));
        }

        if !unicast_builder.is_empty() {
            let response = unicast_builder.build().unwrap_or_else(|x| x);
            self.outgoing.push_back((response, addr));
        }
    }

    fn handle_question(
        &self,
        question: &dns_parser::Question,
        mut builder: AnswerBuilder,
    ) -> AnswerBuilder {
        let hostname = self.services.hostname();

        match question.qtype {
            QueryType::A | QueryType::AAAA | QueryType::All if question.qname == hostname => {
                builder = self.add_ip_rr(hostname, builder, DEFAULT_TTL);
            }
            QueryType::PTR => {
                for svc in self.services.read().find_by_type(&question.qname) {
                    builder = svc.add_ptr_rr(builder, DEFAULT_TTL);
                    builder = svc.add_srv_rr(hostname, builder, DEFAULT_TTL);
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(hostname, builder, DEFAULT_TTL);
                }
            }
            QueryType::SRV => {
                if let Some(svc) = self.services.read().find_by_name(&question.qname) {
                    builder = svc.add_srv_rr(hostname, builder, DEFAULT_TTL);
                    builder = self.add_ip_rr(hostname, builder, DEFAULT_TTL);
                }
            }
            QueryType::TXT => {
                if let Some(svc) = self.services.read().find_by_name(&question.qname) {
                    builder = svc.add_txt_rr(builder, DEFAULT_TTL);
                }
            }
            _ => (),
        }

        builder
    }

    fn add_ip_rr(&self, hostname: &Name, mut builder: AnswerBuilder, ttl: u32) -> AnswerBuilder {
        for iface in net::getifaddrs() {
            if iface.is_loopback() {
                continue;
            }

            match iface.ip() {
                Some(IpAddr::V4(ip)) if !self.is_ipv6 => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::A(ip))
                }
                Some(IpAddr::V6(ip)) if self.is_ipv6 => {
                    builder = builder.add_answer(hostname, QueryClass::IN, ttl, &RRData::AAAA(ip))
                }
                _ => (),
            }
        }

        builder
    }

    fn send_unsolicited(&mut self, svc: &ServiceData, ttl: u32, include_ip: bool) {
        let mut builder =
            dns_parser::Builder::new_response(0, false, true).move_to::<dns_parser::Answers>();
        builder.set_max_size(None);

        let hostname = self.services.hostname();

        builder = svc.add_ptr_rr(builder, ttl);
        builder = svc.add_srv_rr(hostname, builder, ttl);
        builder = svc.add_txt_rr(builder, ttl);
        if include_ip {
            builder = self.add_ip_rr(hostname, builder, ttl);
        }

        if !builder.is_empty() {
            let response = builder.build().unwrap_or_else(|x| x);
            let addr = SocketAddr::new(self.mdns_group(), MDNS_PORT);
            self.outgoing.push_back((response, addr));
        }
    }

    fn mdns_group(&self) -> IpAddr {
        if self.is_ipv6 {
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251))
        } else {
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb))
        }
    }
}

impl Future for FSM {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        while let Async::Ready(cmd) = self.commands.poll().unwrap() {
            match cmd {
                Some(Command::Shutdown) => return Ok(Async::Ready(())),
                Some(Command::SendUnsolicited {
                    svc,
                    ttl,
                    include_ip,
                }) => {
                    self.send_unsolicited(&svc, ttl, include_ip);
                }
                None => {
                    warn!("responder disconnected without shutdown");
                    return Ok(Async::Ready(()));
                }
            }
        }

        self.recv_packets()?;

        loop {
            if let Some(&(ref response, ref addr)) = self.outgoing.front() {
                trace!("sending packet to {:?}", addr);

                match self.socket.poll_send_to(response, addr) {
                    Ok(Async::Ready(_)) => (),
                    Ok(Async::NotReady) => break,
                    Err(err) => warn!("error sending packet {:?}", err),
                }
            } else {
                break;
            }

            self.outgoing.pop_front();
        }

        Ok(Async::NotReady)
    }
}
