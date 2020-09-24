use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::net::{IpAddr, SocketAddr};

use etherparse::{IpHeader, PacketHeaders, TransportHeader};

// I came across pcap by accident- I was searching for a way to interact with network packets directly and searched "rust tcpdump processing".
// I landed on this reddit post: https://www.reddit.com/r/rust/comments/40omrx/simple_packet_sniffer_in_rust/.
// Once I learned that tcpdump and pcap were related, I felt comfortable enough with just settling on pcap as my tool of choice for
// my exploration.
use pcap::{Capture, Device};

// I always knew I was going to model the network I was visualizing as a graph. I don't even know if its the best way sturcture a network, but here I go.
use petgraph::dot::Dot;
use petgraph::graph::NodeIndex;
use petgraph::Graph;

// Decided I wanted to try and pull DNS results for IPs I would sniff through pcap. Just for better readability.
use dns_lookup::lookup_addr;

// I am under the impression that its in every Rust programmer's best interest to derive Debug whenever possible.
// Display doesn't neccesarily need to be implemented, but Debug is important for just literally debugging.
// ParitalEq is derived so that we can compare Hosts when determining if a Host is already in the Graph or not.
// Many packets are referring to the same Hosts over and over so we just want one in the graph for each uniqe IP Address.
#[derive(Debug, PartialEq)]
struct Host {
    address: IpAddr,
    hostname: String,
}

// For elements in the graph model such as Host and Ports, I must implement Display in order to output the graph in dot file format for later visualization with dot visualizers.
impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.hostname)
    }
}

// In the model for the graph of hosts I saw ports as a separate entity from the hosts for visualization purposes. Edges are ports (u16). Nodes are Hosts.
#[derive(PartialEq, Debug)]
struct Ports(Vec<u16>);

// Vecs do not implement display so I had to wrap the Vec and implement Display on the wrapper type.
// The Rust compiler suggested this tactic.
// I did not learn about Formatters (the mutably borrowed f parameter in fmt()) in depth. Just what is available in the Rust docs on Display trait.
impl fmt::Display for Ports {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.iter();
        let mut ss = String::new();
        // format! returns a String. String concatenation borrows its arguments. That is why we borrow the String after creating it.
        // This is because the first string can be saved the effort of being copied over and we can reuse the String buffer to grow
        // to include the concatenated String. The second String is borrowed. That way it can be reused after and the new String will
        // copy its contents over into the first String's potentially expanded buffer when concatenating.
        for l in s {
            ss += &format!("{}, ", l);
        }
        ss.truncate(ss.len() - 2);
        write!(f, "{}", &ss)
    }
}

// I decided to keep ParseError separate from AppError and wrap ParseErrors as a variant of AppErrors.
// I read online about Error handling a bunch and saw different strategies. I just settled on something simple.
#[derive(Debug)]
enum ParseError {
    ReadError(etherparse::ReadError),
    BadIpOrTcp,
}

// To print ParseErrors when logging to console, file, etc.
impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::ReadError(e) => write!(f, "{}", e),
            ParseError::BadIpOrTcp => write!(f, "IP or TCP packet was wonky"),
        }
    }
}

// I wanted a single Error type for application errors since they can be one of many different errors.
// I also think the design Of Result<T, E> enforces this. I don't know precisely how, but I am pretty
// sure it is becasue you should have a conssistent Error type in your Result especially when working
// with combinators. A counter example is Future in Scala, where the Error case is literally anything
// that is an Error. That always annoyed me because it never allowed a programmer to document fully what
// kind of errors are produced by some code. It just told the reader that an Error can occur, but not what Errors
// specifically. Results in Rust force you to enumerate the possible Errors.
// I'm sure you can hack out of this behavior of course.
#[derive(Debug)]
enum AppError {
    ParseError(ParseError),
    DotWriteError(std::io::Error),
}

// To print ParseErrors when logging to console, file, etc.
impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::ParseError(p) => write!(f, "{}", p),
            AppError::DotWriteError(d) => write!(f, "{}", d),
        }
    }
}

// I reused the stdlib types for SocketAddr and just passed around the port embedded in them.
// Later in the pipeline, we convert these into the visual model from earlier.
fn parse_into_socket_addresses(data: &[u8]) -> Result<(SocketAddr, SocketAddr), ParseError> {
    PacketHeaders::from_ethernet_slice(data)
        .map_err(ParseError::ReadError)
        .map(|ph| (ph.ip, ph.transport))
        // FYI: and_then is an equivalent of flatMap in Scala
        .and_then(
            |(ip_header, transport_header)| match (ip_header, transport_header) {
                (Some(IpHeader::Version4(v4)), Some(TransportHeader::Tcp(tcp_header))) => Ok((
                    SocketAddr::from((v4.source, tcp_header.source_port)),
                    SocketAddr::from((v4.destination, tcp_header.destination_port)),
                )),
                (Some(IpHeader::Version6(v6)), Some(TransportHeader::Tcp(tcp_header))) => Ok((
                    SocketAddr::from((v6.source, tcp_header.source_port)),
                    SocketAddr::from((v6.destination, tcp_header.destination_port)),
                )),
                (_, _) => Err(ParseError::BadIpOrTcp),
            },
        )
}

// The only constraints in this generic function is that T (the graph node type) implements PartialEq so we can compare nodes before inserting a duplicate.
// The other constraint is a bit dirty to me, but its what worked. I know my particular graph is Undirected, but I didn't want that to be set so I reused
// EdgeType which is the same constraint the graph lib uses to implement its Directed and Undirected types.
// Everything is borrowed immutably so the memory won't be freed after the fucntion returns and the caller continues to have safe access to the data.
fn get_index_for<T: PartialEq, E, D: petgraph::EdgeType>(
    g: &Graph<T, E, D>,
    t: &T,
) -> Option<NodeIndex> {
    // This syntax is off putting, but let me try and explain.
    // The node_indices method on Graph returns a type called NodeIndices.
    // NodeIndices is a struct wtih some irrelevant fields. What is
    // important is that it implements Iterator. Iterators with properly
    // implemented next methods automatically receive an implementation of
    // find to look for an existing item in the iterator. To find, iterators
    // apply a user supplied function that returns true or false to indicate
    // whether you found what you were looking for was in the current iteration's
    // element. The NodeIndex itself can be dereferenced like any borrow to get
    // the value of the index. On top of that, Graph implements Index on the
    // NodeIndex type and not a &NodeIndex or a borrow of a NodeIndex which
    // is why we must deref. Using that Index implementation we can use the
    // common indexing syntax '[]' on Graphs (and borrowed Graphs, but I'm
    // not sure why except for the fact that usually types are allowed to
    // call its methods or use its traits in both forms). Getting a value from
    // this graph index returns a reference/borrow to a node in the graph.
    // To compare it with our borrowed node of type T, we need to Deref (*) the
    // &T to get a T.
    // FYI both &g[*ni] == t and g[*ni] == *t are valid boolean expressions.
    // Left up to you figure out why/how.
    g.node_indices().find(|ni| g[*ni] == *t)
}

// Simply a DNS lookup using a crate - I didn't want to bother implementing
// hostname lookup myself. Fallsback to the address in String format if lookup fails.
fn lookup_ip_and_fallback(address: &IpAddr) -> String {
    lookup_addr(address).unwrap_or_else(|_| address.to_string())
}

fn insert_if_not_found<T: PartialEq, E, D: petgraph::EdgeType>(
    g: &mut Graph<T, E, D>,
    t: T,
) -> NodeIndex {
    get_index_for(&g, &t).unwrap_or_else(|| g.add_node(t))
}

fn to_graph_model(socket_addrss: (SocketAddr, SocketAddr)) -> (Host, Host, Ports) {
    let (src_socket_address, dst_socket_address) = socket_addrss;
    let src_hostname = lookup_ip_and_fallback(&src_socket_address.ip());
    let dst_hostname = lookup_ip_and_fallback(&dst_socket_address.ip());
    let src_host = Host {
        address: src_socket_address.ip(),
        hostname: src_hostname,
    };
    let dst_host = Host {
        address: dst_socket_address.ip(),
        hostname: dst_hostname,
    };
    let ports = Ports(vec![src_socket_address.port(), dst_socket_address.port()]);

    (src_host, dst_host, ports)
}

fn main() {
    // Just chose my only WLAN (Wireless Local Area Network) interface to listen/sniff.
    let device_name: String = "wlp2s0".to_string();

    // The pcap Rust wrapper closely follows the C pcap interfaces. Its not perfect,
    // but they look basically the same based on the docs on pcaplib I read.
    let devices = Device::list().unwrap();

    // I unwrap a lot when setting the device capture up because if these don't work,
    // then the execution is busted. No reason to keep running.
    let requested_device = devices
        .into_iter()
        .find(|device| device.name == device_name)
        .unwrap();

    let device_desc = requested_device.desc.clone();

    let mut cap = Capture::from_device(requested_device)
        .unwrap()
        .open()
        .unwrap();

    // Chose Undirected only because Directed has more lines (for Hosts that send
    // packets both to and from each other) and it makes the whole graph harder to read.
    let mut my_network: petgraph::graph::UnGraph<Host, Ports> = Graph::new_undirected();

    // While packets come, capture them...
    while let Ok(packet) = cap.next() {
        parse_into_socket_addresses(&packet.data)
            // This is my strategy for keeping Result types consistent.
            // The compiler usually has my back (probably corner cases
            // where this doesn't work, but I don't know them).
            .map_err(AppError::ParseError)
            .map(to_graph_model)
            .map(|(src_host, dst_host, ports)| {
                let src_node_index = insert_if_not_found(&mut my_network, src_host);
                let dst_node_index = insert_if_not_found(&mut my_network, dst_host);

                let nports = my_network
                    .find_edge(src_node_index, dst_node_index)
                    .and_then(|ee| {
                        my_network
                            .edge_references()
                            .enumerate()
                            .find_map(|(i, er)| if i == ee.index() { Some(er) } else { None })
                    })
                    .map(|er| {
                        let ep = &er.weight().0;
                        let np: Vec<u16> = ports
                            .0
                            .iter()
                            .cloned()
                            .filter(|p| ep.iter().find(|ep| ep == &p).is_none())
                            .collect();
                        let mut epc = ep.clone();
                        epc.extend(np);
                        Ports(epc.to_vec())
                    })
                    .unwrap_or(ports);

                my_network.update_edge(src_node_index, dst_node_index, nports);
                format!("{}", Dot::with_config(&my_network, &[]))
            })
            .and_then(|dot_repr| {
                File::create("./my_network.dot")
                    .and_then(|mut f| f.write_all(dot_repr.as_bytes()))
                    .map_err(AppError::DotWriteError)
            })
            .or_else(|e| {
                println!("{}", e);
                Err(e)
            })
            .ok();
    }

    println!(
        "packets stopped being available to consume from captured device {:?}, {:?}",
        device_name, device_desc
    );
}
