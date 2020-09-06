use anyhow::{anyhow, Context, Result};
use log::error;
use pnet::datalink;
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::env;
use std::net::IpAddr;

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        error!("Please specify network interface name");
        std::process::exit(1);
    }
    let ifname = &args[1];
    capture(ifname).unwrap_or_else(|e| error!("{}", e));
}

fn capture(ifname: &str) -> Result<()> {
    use pnet::datalink::Channel::Ethernet;

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == *ifname)
        .with_context(|| {
            format!(
                "Failed to find a network interface from the name {}",
                ifname
            )
        })?;

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(anyhow!("Unhandled channel type")),
        Err(e) => return Err(anyhow!("Failed to create datalink channel: {}", e)),
    };

    loop {
        let packet = EthernetPacket::new(rx.next()?).context("Failed to parse Ethernet packet")?;
        handle_ethernet_frame(ifname, &packet);
    }
}

fn handle_ethernet_frame(ifname: &str, ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ifname, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(ifname, ethernet),
        EtherTypes::Arp => handle_arp_packet(ifname, ethernet),
        _ => println!(
            "[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            ifname,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len(),
        ),
    }
}

fn handle_ipv4_packet(ifname: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            ifname,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", ifname);
    }
}

fn handle_ipv6_packet(ifname: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            ifname,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", ifname);
    }
}

fn handle_arp_packet(ifname: &str, ethernet: &EthernetPacket) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        println!(
            "[{}]: ARP packet: {}({}) > {}({}); operation: {:?}",
            ifname,
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation(),
        );
    } else {
        println!("[{}]: Malformed ARP Packet", ifname);
    }
}

fn handle_transport_protocol(
    ifname: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(ifname, source, destination, packet);
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(ifname, source, destination, packet);
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(ifname, source, destination, packet);
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(ifname, source, destination, packet);
        }
        _ => println!(
            "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            ifname,
            match source {
                IpAddr::V4(..) => "IPv4A",
                IpAddr::V6(..) => "IPv6A",
            },
            source,
            destination,
            protocol,
            packet.len(),
        ),
    }
}

fn handle_udp_packet(ifname: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            ifname,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length(),
        )
    } else {
        println!("[{}]: Malformed UDP Packet", ifname);
    }
}

fn handle_tcp_packet(ifname: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let tcp = TcpPacket::new(packet);

    if let Some(tcp) = tcp {
        println!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            ifname,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len(),
        )
    } else {
        println!("[{}]: Malformed TCP Packet", ifname);
    }
}

fn handle_icmp_packet(ifname: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp = IcmpPacket::new(packet);

    if let Some(icmp) = icmp {
        match icmp.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    ifname,
                    source,
                    destination,
                    packet.get_sequence_number(),
                    packet.get_identifier(),
                );
            }
            IcmpTypes::EchoRequest => {
                let packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    ifname,
                    source,
                    destination,
                    packet.get_sequence_number(),
                    packet.get_identifier(),
                );
            }
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                ifname,
                source,
                destination,
                icmp.get_icmp_type(),
            ),
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", ifname);
    }
}

fn handle_icmpv6_packet(ifname: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp = Icmpv6Packet::new(packet);

    if let Some(icmp) = icmp {
        println!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            ifname,
            source,
            destination,
            icmp.get_icmpv6_type(),
        );
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", ifname);
    }
}
