use libc::{
  c_char,
  c_int,
  c_long,
  c_ushort,
  c_void,
  sockaddr,
  sockaddr_ll,
  socklen_t,
};
use std::ffi::{CString, CStr};
use std::io::{Result, Error, ErrorKind};
use std::os::unix::io::{RawFd, FromRawFd};
use std::mem::{
  size_of,
  zeroed,
  transmute
};

mod asm;

const LICENSE_BUF_SIZE: usize = 128;
const LOG_BUF_FIZE: usize = 4096;
const ETH_P_ALL_NS: c_ushort = (libc::ETH_P_ALL as c_ushort).to_be();

struct BpfProg {
  pub prog_name: String,
  pub fd: RawFd,
  pub license: String,
  pub insns: Vec<asm::Insn>,
  pub load_attr: BpfLoadAttr,
  pub log_buf: [c_char; LOG_BUF_FIZE]
}

struct BpfLoadError(String);

impl From<BpfLoadError> for Error {
  fn from(_: BpfLoadError) -> Self {
    //Error::new(ErrorKind::Other, v.0)
    Error::new(ErrorKind::Other, "Failed to load program")
  }
}

impl BpfProg {
  fn load(
    prog_name: String,
    prog_type: u32, // TODO use enum
    insns: Vec<asm::Insn>
  ) -> Result<Self> {
    let mut log_buf: [c_char; LOG_BUF_FIZE] = [0; LOG_BUF_FIZE];
    // GPLの文字列を c_char の固定長ベクタに詰め込んで後で配列のポインタを渡す
    let license = String::from("GPL");
    let mut license_buf: Vec<c_char> = Vec::with_capacity(LICENSE_BUF_SIZE);
    license.chars().into_iter().take(LICENSE_BUF_SIZE).enumerate().for_each({|e|
      license_buf.insert(e.0, e.1 as c_char)
    });

    let attr = BpfLoadAttr {
      prog_type: prog_type,
      insn_cnt: insns.len() as u32,
      insns: insns.as_ptr(),
      license: license_buf.as_ptr() as *const c_char,
      log_level: 1, /* 1 = debug, 2 = trace */
      log_size: LOG_BUF_FIZE as u32,
      log_buf: log_buf.as_mut_ptr(),
      kern_version: 0,
      prog_flags: 0,
      prog_name: std::ptr::null(),
      prog_ifindex: 0,
      expected_attach_type: 0
    };
    let result = unsafe {
      libc::syscall(
         libc::SYS_bpf,
         5, // BPF_PROG_LOAD
         &attr as *const BpfLoadAttr,
         size_of::<BpfLoadAttr>() as c_long
      )
    };

    if result < 0 {
      let verifier_message: &str = unsafe {
        CStr::from_ptr(log_buf.as_ptr())
      }.to_str().expect("failed to read log buf");
      Err(Error::new(ErrorKind::Other,
         format!("{} {}", Error::last_os_error(), verifier_message))
      )
    }
    else {
      Ok(BpfProg {
        prog_name: prog_name,
        fd: result as RawFd,
        license: license,
        insns: insns,
        load_attr: attr,
        log_buf
      })
    }
  }
}



 /* anonymous struct used by BPF_PROG_LOAD command */
 #[derive(Debug)]
#[repr(C)]
struct BpfLoadAttr {
  prog_type: u32,
  insn_cnt: u32,
  insns: *const asm::Insn,
  license: *const c_char,
  log_level: u32,
  log_size: u32,
  log_buf: *mut c_char,
  kern_version: u32,
  prog_flags: u32,
  prog_name: *const c_char,
  prog_ifindex: u32,
  expected_attach_type: u32
}

trait SocketAddress {
  fn length(&self) -> socklen_t;
  fn as_sockaddr(&self) -> *const sockaddr;
}

impl SocketAddress for sockaddr_ll {
  fn length(&self) -> socklen_t {
    size_of::<sockaddr_ll>() as socklen_t
  }
  fn as_sockaddr(&self) -> *const sockaddr {
    unsafe { transmute::<*const sockaddr_ll, *const sockaddr>(self) }
  }
}

trait SocketOption {
  fn level(&self) -> c_int;
  fn name(&self) -> c_int;
  fn length(&self) -> socklen_t;
  fn value(&self) -> *const c_void;
}

struct AttachBpf {
  prog_fd: RawFd
}

impl SocketOption for AttachBpf {
  fn level(&self) -> c_int {
    libc::SOL_SOCKET
  }
  fn name(&self) -> c_int {
    libc::SO_ATTACH_BPF
  }
  fn length(&self) -> socklen_t {
    size_of::<c_int>() as socklen_t
  }
  fn value(&self) -> *const c_void {
    unsafe { transmute::<&c_int, *const c_void>(&(self.prog_fd)) }
  }
}

fn socket(domain: c_int, ty: c_int, protocol: c_int) -> Result<RawFd> {
  let sock_fd = unsafe { libc::socket(domain, ty, protocol) };
  if sock_fd < 0 {
    Err(Error::last_os_error())
  }
  else {
    Ok(sock_fd)
  }
}

fn new_sockaddr_ll(devname: &str) -> sockaddr_ll {
 let devname_cstring = CString::new(devname.clone()).expect("Failed to allocate device name");
 let mut sll: sockaddr_ll = unsafe { zeroed() };
 sll.sll_family = libc::AF_PACKET as c_ushort;
 sll.sll_ifindex = unsafe { libc::if_nametoindex(devname_cstring.as_ptr()) as c_int };
 sll.sll_protocol = ETH_P_ALL_NS;
 sll
}

fn bind<S>(sock: &RawFd, sockaddr: S) -> Result<()>
  where S: SocketAddress {
  let result = unsafe { libc::bind(sock.clone(), sockaddr.as_sockaddr(), sockaddr.length()) };
  if result < 0 {
    Err(Error::last_os_error())
  }
  else {
    Ok(())
  }
}

fn setsockopt<O>(sock: &RawFd, opt: O) -> Result<()>
  where O: SocketOption {
  let result = unsafe { libc::setsockopt(sock.clone(), opt.level(), opt.name(), opt.value(), opt.length()) };
  if result < 0 {
    Err(Error::last_os_error())
  }
  else {
    Ok(())
  }
}

fn immediate_exit() -> Vec<asm::Insn> {
  vec![
    // BPF_MOV64_IMM(BPF_REG_0, -1),
    asm::Insn{ op: 0x07 | 0xb0 | 0x00, reg: 0, off: 0, imm: (!1 + 1)},
    // BPF_EXIT
    asm::Insn{ op: 0x05 | 0x90, reg: 0, off: 0, imm: 0 },
  ]
}

fn main()   {
  let sock = socket(
     libc::AF_PACKET,
     libc::SOCK_RAW | libc::SOCK_CLOEXEC,
     ETH_P_ALL_NS as i32).expect("Failed to create socket");
  let sockaddr = new_sockaddr_ll("lo");
  bind(&sock, sockaddr).expect("Failed to bind socket to lo device");
  let insns = immediate_exit();
  let prog = BpfProg::load(
    String::from("test"),
    1, // BPF_PROG_TYPE_SOCKET_FILTER
    insns
  ).expect("Failed to load BPF");
  let opt = AttachBpf { prog_fd: prog.fd };
  setsockopt(&sock, opt).expect("Failed to set sockopt");

  let mut buf: [u8; 1500] = [0; 1500];
  let s = unsafe { std::os::unix::net::UnixDatagram::from_raw_fd(sock) };
  loop {
    match s.recv(&mut buf) {
      Err(e) => {
        println!("Failed to read from device: {:?}", e);
        break;
      },
      Ok(read) => {
        println!("read {} bytes", read);
        std::thread::sleep(std::time::Duration::from_secs(1));
      }
    }
  }
}
