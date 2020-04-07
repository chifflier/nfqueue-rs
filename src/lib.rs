//! Netfilter NFQUEUE high-level bindings
//!
//! libnetfilter_queue is a userspace library providing an API to packets that
//! have been queued by the kernel packet filter. It is is part of a system that
//! deprecates the old ip_queue / libipq mechanism.
//!
//! libnetfilter_queue homepage is: http://netfilter.org/projects/libnetfilter_queue/
//!
//! The goal is to provide a library to gain access to packets queued by the
//! kernel packet filter
//!
//! **Using NFQUEUE requires root privileges, or the `CAP_NET_ADMIN` capability**
//!
//! The code is available on [Github](https://github.com/chifflier/nfqueue-rs)
//!
//! # Example
//!
//! ```rust,ignore
//! use std::fmt::Write;
//!
//! fn callback(msg: &nfqueue::Message, _: &mut ()) {
//!     println!(" -> msg: {}", msg);
//!
//!     let payload_data = msg.get_payload();
//!     let mut s = String::new();
//!     for &byte in payload_data {
//!         write!(&mut s, "{:X} ", byte).unwrap();
//!     }
//!     println!("{}", s);
//!
//!     println!("XML\n{}", msg.as_xml_str(&[nfqueue::XMLFormatFlags::XmlAll]).unwrap());
//!
//!     msg.set_verdict(nfqueue::Verdict::Accept);
//! }
//!
//! let mut q = nfqueue::Queue::new(()).unwrap();
//!
//! let rc = q.bind(libc::AF_INET);
//! assert!(rc == 0);
//!
//! q.create_queue(0, callback);
//! q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);
//!
//! q.run_loop();
//! ```

use libc;

pub use crate::hwaddr::*;
mod hwaddr;

pub use crate::message::*;
mod message;

#[derive(Debug)]
pub enum NfqueueError {
    /// The internal `nfq_open` failed.
    Open,
}

impl std::fmt::Display for NfqueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "nfq_open failed")
    }
}

impl std::error::Error for NfqueueError {}

pub type NfqueueResult<T> = std::result::Result<T, NfqueueError>;

type NfqueueHandle = *const libc::c_void;
type NfqueueQueueHandle = *const libc::c_void;

/// Prototype for the callback function, triggered when a packet is received
pub type NfqueueCallback = fn(&Message) -> ();

type NfqueueCCallback = extern "C" fn(
    *const libc::c_void,
    *const libc::c_void,
    *const libc::c_void,
    *const libc::c_void,
);

#[link(name = "netfilter_queue")]
extern "C" {
    // library setup
    fn nfq_open() -> NfqueueHandle;
    fn nfq_close(qh: NfqueueHandle);
    fn nfq_bind_pf(qh: NfqueueHandle, pf: libc::c_int) -> libc::c_int;
    fn nfq_unbind_pf(qh: NfqueueHandle, pf: libc::c_int) -> libc::c_int;

    // queue handling
    fn nfq_fd(h: NfqueueHandle) -> libc::c_int;
    fn nfq_create_queue(
        qh: NfqueueHandle,
        num: u16,
        cb: NfqueueCCallback,
        data: *mut libc::c_void,
    ) -> NfqueueQueueHandle;
    fn nfq_destroy_queue(qh: NfqueueHandle) -> libc::c_int;
    fn nfq_handle_packet(qh: NfqueueHandle, buf: *mut libc::c_void, rc: libc::c_int)
        -> libc::c_int;
    fn nfq_set_mode(gh: NfqueueQueueHandle, mode: u8, range: u32) -> libc::c_int;
    fn nfq_set_queue_maxlen(gh: NfqueueQueueHandle, queuelen: u32) -> libc::c_int;
}

/// Copy modes
pub enum CopyMode {
    /// Do not copy packet contents nor metadata
    CopyNone,
    /// Copy only packet metadata, not payload
    CopyMeta,
    /// Copy packet metadata and not payload
    CopyPacket,
}
const NFQNL_COPY_NONE: u8 = 0x00;
const NFQNL_COPY_META: u8 = 0x01;
const NFQNL_COPY_PACKET: u8 = 0x02;

/// Opaque struct `Queue`: abstracts an NFLOG queue
pub struct Queue<T> {
    qh: NfqueueHandle,
    qqh: NfqueueQueueHandle,
    cb: Option<fn(&Message, &mut T) -> ()>,
    data: T,
}

impl<T> Drop for Queue<T> {
    fn drop(&mut self) {
        unsafe { nfq_close(self.qh) };
    }
}

impl<T: Send> Queue<T> {
    /// Creates a new Queue and opens a NFLOG handler
    ///
    /// This function obtains a netfilter queue connection handle. When you are
    /// finished with the handle returned by this function, you should destroy it
    /// by calling `close()`.
    /// A new netlink connection is obtained internally
    /// and associated with the queue connection handle returned.
    pub fn new(data: T) -> NfqueueResult<Queue<T>> {
        let qh = unsafe { nfq_open() };
        if qh.is_null() {
            return Err(NfqueueError::Open);
        }

        Ok(Queue {
            qh,
            qqh: std::ptr::null_mut(),
            cb: None,
            data,
        })
    }

    /// Bind a nfqueue handler to a given protocol family
    ///
    /// Binds the given queue connection handle to process packets belonging to
    /// the given protocol family (ie. `PF_INET`, `PF_INET6`, etc).
    ///
    /// Arguments
    ///
    /// * `pf` - Protocol family (usually `AF_INET` or `AF_INET6`)
    ///
    /// Remarks:
    ///
    /// **Requires root privileges**
    pub fn bind(&self, pf: libc::c_int) -> i32 {
        unsafe { nfq_bind_pf(self.qh, pf) }
    }

    /// Unbinds the nfqueue handler from a protocol family
    ///
    /// Unbinds the given nfqueue handle from processing packets belonging to the
    /// given protocol family.
    ///
    /// Arguments
    ///
    /// * `pf` - Protocol family (usually `AF_INET` or `AF_INET6`)
    ///
    /// Remarks:
    ///
    /// **Requires root privileges**
    pub fn unbind(&self, pf: libc::c_int) -> i32 {
        unsafe { nfq_unbind_pf(self.qh, pf) }
    }

    /// Returns the C file descriptor associated with the nfqueue handler
    ///
    /// This function returns a file descriptor that can be used for
    /// communication over the netlink connection associated with the given queue
    /// connection handle.
    pub fn fd(&self) -> i32 {
        unsafe { nfq_fd(self.qh) }
    }

    /// create a new queue handler bind it to a queue number, and to a callback.
    ///
    /// Creates a new queue handle, and returns it. The new queue is identified
    /// by `num`, and the callback specified by `cb` will be called for each
    /// enqueued packet.
    ///
    /// Arguments
    ///
    /// * `num`: the number of the queue to bind to
    /// * `cb`: callback function to call for each queued packet
    pub fn create_queue(&mut self, num: u16, cb: fn(&Message, &mut T)) {
        assert!(self.qqh.is_null());
        let self_ptr = &*self as *const Queue<T> as *mut libc::c_void;
        self.cb = Some(cb);
        self.qqh = unsafe { nfq_create_queue(self.qh, num, real_callback::<T>, self_ptr) };
    }

    /// Destroys a group handle
    ///
    /// Removes the binding for the specified queue handle. This call also
    /// unbind from the nfqueue handler, so you don't need to call any extra
    /// function.
    pub fn destroy_queue(&mut self) {
        assert!(!self.qqh.is_null());
        unsafe {
            nfq_destroy_queue(self.qqh);
        }
        self.qqh = std::ptr::null_mut();
    }

    /// Set the amount of packet data that nfqueue copies to userspace
    ///
    /// Arguments:
    ///
    /// * `mode` - The part of the packet that we are interested in
    /// * `range` - Size of the packet that we want to get
    ///
    /// `mode` can be one of:
    ///
    /// * `NFQNL_COPY_NONE` - do not copy any data
    /// * `NFQNL_COPY_META` - copy only packet metadata
    /// * `NFQNL_COPY_PACKET` - copy entire packet
    pub fn set_mode(&self, mode: CopyMode, range: u32) {
        assert!(!self.qqh.is_null());
        let c_mode = match mode {
            CopyMode::CopyNone => NFQNL_COPY_NONE,
            CopyMode::CopyMeta => NFQNL_COPY_META,
            CopyMode::CopyPacket => NFQNL_COPY_PACKET,
        };
        unsafe {
            nfq_set_mode(self.qqh, c_mode, range);
        }
    }

    /// Set kernel queue maximum length parameter
    ///
    /// Arguments:
    ///
    /// * `queuelen` - The length of the queue
    ///
    /// Sets the size of the queue in kernel. This fixes the maximum number of
    /// packets the kernel will store before internally before dropping upcoming
    /// packets
    pub fn set_queue_maxlen(&self, queuelen: u32) {
        assert!(!self.qqh.is_null());
        unsafe {
            nfq_set_queue_maxlen(self.qqh, queuelen);
        }
    }

    /// Runs an infinite loop, waiting for packets and triggering the callback.
    pub fn run_loop(&self) {
        assert!(!self.qqh.is_null());
        assert!(!self.cb.is_none());

        let fd = self.fd();
        let mut buf: [u8; 65536] = [0; 65536];
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_void;
        let buf_len = buf.len() as libc::size_t;

        loop {
            let rc = unsafe { libc::recv(fd, buf_ptr, buf_len, 0) };
            if rc < 0 {
                panic!("error in recv()");
            };

            let rv = unsafe { nfq_handle_packet(self.qh, buf_ptr, rc as libc::c_int) };
            if rv < 0 {
                println!("error in nfq_handle_packet()");
            }; // not critical
        }
    }
}

#[doc(hidden)]
extern "C" fn real_callback<T>(
    qqh: *const libc::c_void,
    _nfmsg: *const libc::c_void,
    nfad: *const libc::c_void,
    data: *const libc::c_void,
) {
    let raw: *mut Queue<T> = data as *mut Queue<T>;

    let q = &mut unsafe { &mut *raw };
    let msg = Message::new(qqh, nfad);

    match q.cb {
        None => panic!("no callback registered"),
        Some(callback) => {
            callback(&msg, &mut q.data);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn nfqueue_open() {
        let q = crate::Queue::new(()).unwrap();
        let raw = q.qh as *const i32;
        println!("nfq_open: 0x{:x}", unsafe { *raw });
    }

    #[test]
    #[ignore]
    fn nfqueue_bind() {
        let q = Queue::new(()).unwrap();
        let raw = q.qh as *const i32;
        println!("nfq_open: 0x{:x}", unsafe { *raw });

        let rc = q.bind(libc::AF_INET);
        println!("q.bind: {}", rc);
    }
}
