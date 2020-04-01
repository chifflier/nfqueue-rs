use libc;
use nfqueue;

struct State {
    count: u32,
}

impl State {
    pub fn new() -> State {
        State { count: 0 }
    }
}

fn queue_callback(msg: &nfqueue::Message, state: &mut State) {
    println!("Packet received [id: 0x{:x}]\n", msg.get_id());

    println!(" -> msg: {}", msg);

    println!(
        "XML\n{}",
        msg.as_xml_str(&[nfqueue::XMLFormatFlags::XmlAll]).unwrap()
    );

    state.count += 1;
    println!("count: {}", state.count);

    msg.set_verdict(nfqueue::Verdict::Accept);
}

fn main() {
    let mut q = nfqueue::Queue::new(State::new()).unwrap();

    println!("nfqueue example program: print packets metadata and accept packets");

    q.unbind(libc::AF_INET); // ignore result, failure is not critical here

    let rc = q.bind(libc::AF_INET);
    assert!(rc == 0);

    q.create_queue(0, queue_callback);
    q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);

    q.run_loop();
}
