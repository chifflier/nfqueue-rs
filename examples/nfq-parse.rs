// Some code borrowed from https://github.com/libpnet/libpnet/blob/master/examples/packetdump.rs

use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::net::IpAddr;

struct State {
    count: u32,
}

impl State {
    pub fn new() -> State {
        State { count: 0 }
    }
}

fn print_bytes(array: &[u8]) {
    for byte in array {
        print!("{:02X} ", &byte);
    }
    for _ in array.len()..16 {
        print!("   ");
    }
    print!("  |");
    for byte in array {
        print_ascii(byte);
    }
    for _ in array.len()..16 {
        print!(" ");
    }
    println!("|");
}

fn print_ascii(byte: &u8) {
    if *byte > 32 && *byte < 127 {
        let letter = *byte as char;
        print!("{}", letter);
    } else {
        print!(".");
    }
}

fn print_hexdump(data: &[u8]) {
    for line in data.chunks(16) {
        print_bytes(line);
    }
}

fn handle_icmp_packet(id: u32, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    id,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    id,
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );
            }
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                id,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
        println!("icmp payload:");
        print_hexdump(icmp_packet.payload());
    } else {
        println!("[{}]: Malformed ICMP Packet", id);
    }
}

fn handle_udp_packet(id: u32, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            id,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );
        println!("udp payload:");
        print_hexdump(udp.payload());
    } else {
        println!("[{}]: Malformed UDP Packet", id);
    }
}

fn handle_tcp_packet(id: u32, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            id,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
        println!("tcp payload:");
        print_hexdump(tcp.payload());
    } else {
        println!("[{}]: Malformed TCP Packet", id);
    }
}

fn handle_transport_protocol(
    id: u32,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(id, source, destination, packet),
        IpNextHeaderProtocols::Udp => handle_udp_packet(id, source, destination, packet),
        IpNextHeaderProtocols::Tcp => handle_tcp_packet(id, source, destination, packet),
        _ => println!(
            "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            id,
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn queue_callback(msg: &nfqueue::Message, state: &mut State) {
    println!("\n---");
    println!("Packet received [id: 0x{:x}]\n", msg.get_id());

    state.count += 1;

    // assume IPv4
    let header = Ipv4Packet::new(msg.get_payload());
    match header {
        Some(h) => handle_transport_protocol(
            msg.get_id(),
            IpAddr::V4(h.get_source()),
            IpAddr::V4(h.get_destination()),
            h.get_next_level_protocol(),
            h.payload(),
        ),
        None => println!("Malformed IPv4 packet"),
    }

    msg.set_verdict(nfqueue::Verdict::Accept);
}

fn main() {
    let mut q = nfqueue::Queue::new(State::new()).unwrap();
    println!("nfqueue example program: parse packet protocol layers and accept packet");

    q.unbind(libc::AF_INET); // ignore result, failure is not critical here

    let rc = q.bind(libc::AF_INET);
    assert!(rc == 0);

    q.create_queue(0, queue_callback);
    q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);

    q.run_loop();
}
