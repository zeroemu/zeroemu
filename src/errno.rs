//! Linux errno values (identical on arm64 and x86_64).

pub const ENOENT: i64 = 2;
pub const EIO: i64 = 5;
pub const EBADF: i64 = 9;
pub const EAGAIN: i64 = 11;
pub const ENOMEM: i64 = 12;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const ENODEV: i64 = 19;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const EMFILE: i64 = 24;
pub const ENOTTY: i64 = 25;
pub const ESPIPE: i64 = 29;
pub const EROFS: i64 = 30;
pub const ERANGE: i64 = 34;
pub const ENOSYS: i64 = 38;
pub const ELOOP: i64 = 40;
pub const ESRCH: i64 = 3;
pub const EINTR: i64 = 4;
pub const ECHILD: i64 = 10;
pub const EEXIST: i64 = 17;
pub const ENOEXEC: i64 = 8;
pub const E2BIG: i64 = 7;
pub const EPIPE: i64 = 32;
pub const ENAMETOOLONG: i64 = 36;
pub const ETIMEDOUT: i64 = 110;
pub const EOPNOTSUPP: i64 = 95;
pub const EPERM: i64 = 1;
pub const ENOTSOCK: i64 = 88;
pub const EPROTOTYPE: i64 = 91;
pub const ENOPROTOOPT: i64 = 92;
pub const EPROTONOSUPPORT: i64 = 93;
pub const EAFNOSUPPORT: i64 = 97;
pub const EADDRINUSE: i64 = 98;
pub const EISCONN: i64 = 106;
pub const ENOTCONN: i64 = 107;
pub const ECONNREFUSED: i64 = 111;
pub const ENXIO: i64 = 6;
pub const EBUSY: i64 = 16;
pub const EXDEV: i64 = 18;
pub const EFBIG: i64 = 27;
pub const ENOTEMPTY: i64 = 39;

/// A Linux errno carried inside an `io::Error` (host error codes differ).
#[derive(Debug)]
pub struct Errno(pub i64);

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "errno {}", self.0)
    }
}

impl std::error::Error for Errno {}

pub fn io_err(e: i64) -> std::io::Error {
    std::io::Error::other(Errno(e))
}
