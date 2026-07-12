use serde::{Deserialize, Serialize};

// ── File descriptor passing (SCM_RIGHTS) ──────────────────────────

/// Send a file descriptor over a Unix domain socket via SCM_RIGHTS.
pub fn send_fd(fd: i32, fd_to_send: i32) -> Result<(), String> {
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as libc::c_uint) };
    let cmsg_space_usize = cmsg_space as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space_usize];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space_usize;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err("CMSG_FIRSTHDR returned null".to_string());
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        let cmsg_len_val = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as libc::c_uint);
        (*cmsg).cmsg_len = cmsg_len_val as _;
        std::ptr::write(libc::CMSG_DATA(cmsg) as *mut libc::c_int, fd_to_send);
    }

    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

/// Receive a file descriptor over a Unix domain socket via SCM_RIGHTS.
pub fn recv_fd(fd: i32) -> Result<i32, String> {
    let mut dummy = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: dummy.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };

    let cmsg_space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as libc::c_uint) };
    let cmsg_space_usize = cmsg_space as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space_usize];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space_usize;

    let ret = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err("no cmsg header received".to_string());
        }
        if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
            return Err("expected SCM_RIGHTS ancillary data".to_string());
        }
        let received_fd = std::ptr::read(libc::CMSG_DATA(cmsg) as *const libc::c_int);
        Ok(received_fd)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CallMsg {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub dll: String,
    #[serde(rename = "fn")]
    pub function: String,
    pub args: Vec<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReplyMsg {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub result: serde_json::Value,
}

fn write_all(fd: i32, buf: &[u8]) -> Result<(), String> {
    let mut remaining = buf.len();
    let mut offset = 0;
    while remaining > 0 {
        let n = unsafe {
            libc::write(
                fd,
                buf.as_ptr().add(offset) as *const libc::c_void,
                remaining,
            )
        };
        if n <= 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        remaining -= n as usize;
        offset += n as usize;
    }
    Ok(())
}

fn read_exact(fd: i32, buf: &mut [u8]) -> Result<(), String> {
    let mut remaining = buf.len();
    let mut offset = 0;
    while remaining > 0 {
        let n = unsafe {
            libc::read(
                fd,
                buf.as_mut_ptr().add(offset) as *mut libc::c_void,
                remaining,
            )
        };
        if n <= 0 {
            if n == 0 {
                return Err("EOF".to_string());
            }
            return Err(std::io::Error::last_os_error().to_string());
        }
        remaining -= n as usize;
        offset += n as usize;
    }
    Ok(())
}

fn send_json<T: Serialize>(fd: i32, msg: &T) -> Result<(), String> {
    let data = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    let len = data.len() as u32;
    write_all(fd, &len.to_le_bytes())?;
    write_all(fd, &data)
}

fn recv_json<T: serde::de::DeserializeOwned>(fd: i32) -> Result<T, String> {
    let mut len_buf = [0u8; 4];
    read_exact(fd, &mut len_buf)?;
    let json_len = u32::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; json_len];
    read_exact(fd, &mut buf)?;
    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}

pub fn send_msg(fd: i32, msg: &CallMsg) -> Result<(), String> {
    send_json(fd, msg)
}

pub fn recv_msg(fd: i32) -> Result<CallMsg, String> {
    recv_json(fd)
}

pub fn send_reply(fd: i32, msg: &ReplyMsg) -> Result<(), String> {
    send_json(fd, msg)
}

pub fn recv_reply(fd: i32) -> Result<ReplyMsg, String> {
    recv_json(fd)
}

/// Serialize a repr(C) struct to a JSON value by encoding its raw bytes.
///
/// Safety: T must be plain-old-data with no interior pointers that need
/// relocation (but since we use fork-based IPC with shared address space,
/// pointers remain valid on the host side).
pub fn struct_to_value<T>(s: &T) -> serde_json::Value {
    let bytes =
        unsafe { std::slice::from_raw_parts(s as *const T as *const u8, std::mem::size_of::<T>()) };
    serde_json::json!(bytes.to_vec())
}

/// Deserialize a repr(C) struct from a JSON value containing raw bytes.
///
/// Safety: T must have the exact same ABI layout as the bytes were serialized
/// from. Returns an error if the byte count doesn't match.
pub fn value_to_struct<T>(v: &serde_json::Value) -> Result<T, String> {
    let bytes: Vec<u8> = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
    let expected = std::mem::size_of::<T>();
    if bytes.len() != expected {
        return Err(format!(
            "struct byte size mismatch: expected {expected}, got {}",
            bytes.len()
        ));
    }
    unsafe { Ok(std::ptr::read_unaligned(bytes.as_ptr() as *const T)) }
}

/// Run the host-side message loop.
///
/// Reads call messages from `fd`, hands each (dll, function, args) to the
/// provided `handler` closure, and sends the handler's return value back as
/// a reply.  The handler returns `None` to break the loop (e.g. after an
/// ExitProcess call that has already called libc::exit).
///
/// Returns a receive error to the host so it can report child-process state.
pub fn host_loop<F>(fd: i32, handler: F) -> Result<(), String>
where
    F: Fn(&str, &str, &[serde_json::Value]) -> Option<serde_json::Value>,
{
    loop {
        let msg = match recv_msg(fd) {
            Ok(m) => m,
            Err(e) => return Err(e),
        };

        let result = match handler(&msg.dll, &msg.function, &msg.args) {
            Some(v) => v,
            None => break,
        };

        let reply = ReplyMsg {
            msg_type: "reply".to_string(),
            result,
        };

        if let Err(e) = send_reply(fd, &reply) {
            eprintln!("weave: host_loop send error: {e}");
            break;
        }
    }
    Ok(())
}
