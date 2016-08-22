extern crate nfqueue;
extern crate libc;

fn queue_callback(msg: &nfqueue::Message) {
    println!("Packet received [id: 0x{:x}]\n", msg.get_id());

    println!(" -> msg: {}", msg);

    msg.set_verdict(nfqueue::Verdict::Accept);

    println!("XML\n{}", msg.as_xml_str(&[nfqueue::XMLFormatFlags::XmlAll]).unwrap());
}

fn main() {
    let mut q = nfqueue::Queue::new();
    println!("nfqueue example program: print packets metadata and accept packets");

    q.open();
    q.unbind(libc::AF_INET); // ignore result, failure is not critical here


    let rc = q.bind(libc::AF_INET);
    assert!(rc == 0);

    q.create_queue(0, queue_callback);
    q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);


    q.run_loop();



    q.close();
}
