use std::os::fd::RawFd;

const TUNSETIFF: u64 = 0x400454ca;
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;

#[repr(C)]
struct Ifreq {
    name: [u8; 16],
    flags: u16,
}

pub fn open_tun(name: &str) -> std::io::Result<RawFd> {
    let path = std::ffi::CString::new("/dev/net/tun").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut ifr = Ifreq {
        name: [0u8; 16],
        flags: IFF_TUN | IFF_NO_PI,
    };
    let nb = name.as_bytes();
    ifr.name[..nb.len().min(15)].copy_from_slice(&nb[..nb.len().min(15)]);
    if unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut ifr) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(e);
    }
    Ok(fd)
}

pub fn tun_close(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

pub fn set_nonblock(fd: RawFd) {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags >= 0 {
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    }
}

pub fn tun_read(fd: RawFd, buf: &mut [u8]) -> isize {
    unsafe { libc::read(fd, buf.as_mut_ptr() as _, buf.len()) }
}

pub fn tun_write(fd: RawFd, buf: &[u8]) -> isize {
    unsafe { libc::write(fd, buf.as_ptr() as _, buf.len()) }
}
