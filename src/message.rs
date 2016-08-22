extern crate libc;

use hwaddr::*;
use std;

type NfqueueData = *const libc::c_void;

/// Opaque struct `Message`: abstracts NFLOG data representing a packet data and metadata
pub struct Message {
    qqh  : *const libc::c_void,
    nfad : NfqueueData,
    id   : u32,
}

#[derive(Debug)]
pub enum NfqueueError {
    NoSuchAttribute,
}

/// Decision on the packet
pub enum Verdict {
    /// Discard the packet
    Drop,
    /// Accept the packet (continue iterations)
    Accept,
    /// Gone away
    Stolen,
    /// Inject the packet into a different queue ((the target queue number is in the high 16 bits of the verdict)
    Queue,
    /// Iterate the same cycle one more
    Repeat,
    /// Accept, but don't continue iterations
    Stop,
}

const NF_DROP   : u32 = 0x0000;
const NF_ACCEPT : u32 = 0x0001;
const NF_STOLEN : u32 = 0x0002;
const NF_QUEUE  : u32 = 0x0003;
const NF_REPEAT : u32 = 0x0004;
const NF_STOP   : u32 = 0x0005;

fn u32_of_verdict(v: Verdict) -> u32 {
    match v {
        Verdict::Drop   => NF_DROP,
        Verdict::Accept => NF_ACCEPT,
        Verdict::Stolen => NF_STOLEN,
        Verdict::Queue  => NF_QUEUE,
        Verdict::Repeat => NF_REPEAT,
        Verdict::Stop   => NF_STOP,
    }
}

/// XML formatting flags
pub enum XMLFormatFlags {
    XmlHw,
    XmlMark,
    XmlDev,
    XmlPhysDev,
    XmlPayload,
    XmlTime,
    XmlAll,
}

const NFQ_XML_HW      : u32  = (1 << 0);
const NFQ_XML_MARK    : u32  = (1 << 1);
const NFQ_XML_DEV     : u32  = (1 << 2);
const NFQ_XML_PHYSDEV : u32  = (1 << 3);
const NFQ_XML_PAYLOAD : u32  = (1 << 4);
const NFQ_XML_TIME    : u32  = (1 << 5);
const NFQ_XML_ALL     : u32  = (!0u32);

/// Hardware address
#[repr(C)]
struct NfMsgPacketHw {
    /// Hardware address length
    pub hw_addrlen : u16,
    /// Padding (should be ignored)
    pub _pad : u16,
    /// The hardware address
    pub hw_addr : [u8;8],
}

/// Metaheader wrapping a packet
#[repr(C)]
pub struct NfMsgPacketHdr {
    /// unique ID of the packet
    pub packet_id : u32,
    /// hw protocol (network order)
    pub hw_protocol : u16,
    /// Netfilter hook
    pub hook : u8,
}

#[link(name = "netfilter_queue")]
extern {
    // queue handling
    //fn nfq_set_verdict(qqh: *const libc::c_void, id: u32, verdict: u32, data_len: u32, data: *const libc::c_uchar);
    // requires netfilter_queue >= 1.0
    fn nfq_set_verdict2(qqh: *const libc::c_void, id: u32, verdict: u32, mark: u32, data_len: u32, data: *const libc::c_uchar);

    // message parsing functions
    fn nfq_get_msg_packet_hdr(nfad: NfqueueData) -> *const libc::c_void;
    fn nfq_get_nfmark (nfad: NfqueueData) -> u32;
    fn nfq_get_timestamp (nfad: NfqueueData, tv: *mut libc::timeval) -> u32;
    fn nfq_get_indev (nfad: NfqueueData) -> u32;
    fn nfq_get_physindev (nfad: NfqueueData) -> u32;
    fn nfq_get_outdev (nfad: NfqueueData) -> u32;
    fn nfq_get_physoutdev (nfad: NfqueueData) -> u32;

    fn nfq_get_packet_hw (nfad: NfqueueData) -> *const NfMsgPacketHw;
    fn nfq_get_payload (nfad: NfqueueData, data: &*mut libc::c_void) -> libc::c_int;

    // printing functions
    fn nfq_snprintf_xml (buf: *mut u8, rem: libc::size_t, tb: NfqueueData, flags: libc::c_uint) -> libc::c_int;
}

impl Message {
    /// Create a `Messsage` from a valid NfqueueData pointer
    ///
    /// **This function should never be called directly**
    #[doc(hidden)]
    pub fn new(qqh: *const libc::c_void, nfad: *const libc::c_void) -> Message {
        let msg_hdr = unsafe { nfq_get_msg_packet_hdr(nfad) as *const NfMsgPacketHdr };
        assert!(!msg_hdr.is_null());
        let id = u32::from_be( unsafe{(*msg_hdr).packet_id} );
        Message {
            qqh : qqh,
            nfad: nfad,
            id : id,
        }
    }

    /// Returns the unique ID of the packet
    pub fn get_id(&self) -> u32 {
        self.id
    }

    /// Get the packet mark
    pub fn get_nfmark(&self) -> u32 {
        return unsafe { nfq_get_nfmark(self.nfad) };
    }

    /// Get the packet timestamp
    pub fn get_timestamp(&self) -> Result<libc::timeval,NfqueueError> {
        let mut tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let rc = unsafe { nfq_get_timestamp(self.nfad,&mut tv) };
        match rc {
            0 => Ok(tv),
            _ => Err(NfqueueError::NoSuchAttribute),
        }
    }

    /// Get the interface that the packet was received through
    ///
    /// Returns the index of the device the packet was received via.
    /// If the returned index is 0, the packet was locally generated or the
    /// input interface is not known (ie. `POSTROUTING`?).
    pub fn get_indev(&self) -> u32 {
        return unsafe { nfq_get_indev(self.nfad) };
    }

    /// Get the physical interface that the packet was received through
    ///
    /// Returns the index of the physical device the packet was received via.
    /// If the returned index is 0, the packet was locally generated or the
    /// physical input interface is no longer known (ie. `POSTROUTING`?).
    pub fn get_physindev(&self) -> u32 {
        return unsafe { nfq_get_physindev(self.nfad) };
    }

    /// Get the interface that the packet will be routed out
    ///
    /// Returns the index of the device the packet will be sent out.
    /// If the returned index is 0, the packet is destined to localhost or
    /// the output interface is not yet known (ie. `PREROUTING`?).
    pub fn get_outdev(&self) -> u32 {
        return unsafe { nfq_get_outdev(self.nfad) };
    }

    /// Get the physical interface that the packet will be routed out
    ///
    /// Returns the index of the physical device the packet will be sent out.
    /// If the returned index is 0, the packet is destined to localhost or
    /// the physical output interface is not yet known (ie. `PREROUTING`?).
    pub fn get_physoutdev(&self) -> u32 {
        return unsafe { nfq_get_physoutdev(self.nfad) };
    }





    /// Get hardware address
    ///
    /// Retrieves the hardware address associated with the given packet.
    ///
    /// For ethernet packets, the hardware address returned (if any) will be
    /// the MAC address of the packet *source* host.
    ///
    /// The destination MAC address is not
    /// known until after POSTROUTING and a successful ARP request, so cannot
    /// currently be retrieved.
    pub fn get_packet_hw<'a>(&'a self) -> Result<HwAddr<'a>,NfqueueError> {
        let c_hw = unsafe { nfq_get_packet_hw(self.nfad) };

        if c_hw == std::ptr::null() {
            return Err(NfqueueError::NoSuchAttribute);
        }

        let c_len = u16::from_be(unsafe{(*c_hw).hw_addrlen}) as usize;
        match c_len {
            0 => Err(NfqueueError::NoSuchAttribute),
            _ => Ok( HwAddr::new(unsafe{&((*c_hw).hw_addr)[1..c_len]})),
        }
    }



    /// Issue a verdict on a packet
    ///
    /// Notifies netfilter of the userspace verdict for the given packet.
    ///
    /// Every queued packet **must** have a verdict specified by userspace,
    /// either by calling this function, or by calling any other
    /// `set_verdict_*` function.
    ///
    /// Arguments
    ///
    /// * `verdict`: verdict to return to netfilter (`Verdict::Accept`,
    ///   `Verdict::Drop`, ...)
    pub fn set_verdict(&self, verdict: Verdict) {
        assert!(!self.qqh.is_null());
        let c_verdict = u32_of_verdict(verdict);
        //unsafe { nfq_set_verdict(self.qqh, self.id, c_verdict, 0, std::ptr::null_mut()) };
        unsafe { nfq_set_verdict2(self.qqh, self.id, c_verdict, 0, 0, std::ptr::null_mut()) };
    }

    /// Issue a verdict on a packet, with a mark
    ///
    /// Notifies netfilter of the userspace verdict for the given packet.
    ///
    /// Every queued packet **must** have a verdict specified by userspace,
    /// either by calling this function, or by calling any other
    /// `set_verdict_*` function.
    ///
    /// Arguments
    ///
    /// * `verdict`: verdict to return to netfilter (`Verdict::Accept`,
    ///   `Verdict::Drop`, ...)
    /// * `mark`: the mark to put on the packet, in network-byte order
    pub fn set_verdict_mark(&self, verdict: Verdict, mark: u32) {
        assert!(!self.qqh.is_null());
        let c_verdict = u32_of_verdict(verdict);
        //unsafe { nfq_set_verdict(self.qqh, self.id, c_verdict, 0, std::ptr::null_mut()) };
        unsafe { nfq_set_verdict2(self.qqh, self.id, c_verdict, mark, 0, std::ptr::null_mut()) };
    }

    /// Issue a verdict on a packet, with a mark and new data
    ///
    /// Notifies netfilter of the userspace verdict for the given packet.
    /// The new packet will replace the one that was queued.
    ///
    /// Every queued packet **must** have a verdict specified by userspace,
    /// either by calling this function, or by calling any other
    /// `set_verdict_*` function.
    ///
    /// Arguments
    ///
    /// * `verdict`: verdict to return to netfilter (`Verdict::Accept`,
    ///   `Verdict::Drop`, ...)
    /// * `mark`: the mark to put on the packet, in network-byte order
    /// * `data`: the new packet
    pub fn set_verdict_full(&self, verdict: Verdict, mark: u32, data: &[u8]) {
        assert!(!self.qqh.is_null());
        let c_verdict = u32_of_verdict(verdict);
        let data_ptr = data.as_ptr() as *const libc::c_uchar;
        let data_len = data.len() as u32;
        //unsafe { nfq_set_verdict(self.qqh, self.id, c_verdict, 0, std::ptr::null_mut()) };
        unsafe { nfq_set_verdict2(self.qqh, self.id, c_verdict, mark, data_len, data_ptr) };
    }

    /// Get payload
    ///
    /// Depending on set_mode, we may not have a payload.
    /// The actual amount and type of data retrieved by this function will
    /// depend on the mode set with the `set_mode()` function.
    pub fn get_payload<'a>(&'a self) -> &'a [u8] {
        let c_ptr = std::ptr::null_mut();
        let payload_len = unsafe { nfq_get_payload(self.nfad, &c_ptr) };
        let payload : &[u8] = unsafe { std::slice::from_raw_parts(c_ptr as *mut u8, payload_len as usize) };

        return payload;
    }

    /// Print the queued packet in XML format into a buffer
    pub fn as_xml_str(&self, flags: &[XMLFormatFlags]) -> Result<String,std::str::Utf8Error> {
        // if buffer size is smaller than output, nfq_snprintf_xml will fail
        let mut buf : [u8;65536] = [0;65536];
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_uchar;
        let buf_len = buf.len() as libc::size_t;

        let xml_flags = flags.iter().map(|flag| {
            match *flag {
                XMLFormatFlags::XmlHw      => NFQ_XML_HW,
                XMLFormatFlags::XmlMark    => NFQ_XML_MARK,
                XMLFormatFlags::XmlDev     => NFQ_XML_DEV,
                XMLFormatFlags::XmlPhysDev => NFQ_XML_PHYSDEV,
                XMLFormatFlags::XmlPayload => NFQ_XML_PAYLOAD,
                XMLFormatFlags::XmlTime    => NFQ_XML_TIME,
                XMLFormatFlags::XmlAll     => NFQ_XML_ALL,
            }
        }).fold(0u32, |acc, i| acc | i);

        let rc = unsafe { nfq_snprintf_xml(buf_ptr, buf_len, self.nfad, xml_flags) };
        if rc < 0 { panic!("nfq_snprintf_xml"); } // XXX see snprintf error codes

        match std::str::from_utf8(&buf) {
            Ok(v) => Ok(v.to_string()),
            Err(e) => Err(e),
        }
    }
}

use std::fmt;
use std::fmt::Write;

impl fmt::Display for Message {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let payload_data = self.get_payload();
        let mut s = String::new();
        for &byte in payload_data {
            write!(&mut s, "{:X} ", byte).unwrap();
        }
        write!(out, "{}", s)
    }
}

