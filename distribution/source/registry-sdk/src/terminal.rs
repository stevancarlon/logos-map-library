// SPDX-License-Identifier: MIT OR Apache-2.0
//! Secret prompts must disable echo before the prompt becomes visible.
#[cfg(unix)]
pub fn prompt_secret(prompt: &str) -> std::io::Result<String> {
    use std::{fs::OpenOptions, io::Write, os::fd::AsRawFd};
    let mut terminal = OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let fd = terminal.as_raw_fd();
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: terminal is a live descriptor and original points to writable
    // termios storage. It is read only after tcgetattr reports success.
    if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: successful tcgetattr initialized the entire termios value.
    let original = unsafe { original.assume_init() };
    let mut hidden = original;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
    // SAFETY: fd remains open and hidden is an initialized termios value.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    struct Restore(i32, libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: this guard is dropped before terminal, keeping fd alive.
            unsafe {
                libc::tcsetattr(self.0, libc::TCSANOW, &self.1);
            }
        }
    }
    let _restore = Restore(fd, original);
    terminal.write_all(prompt.as_bytes())?;
    terminal.flush()?;
    // rpassword restores the already-hidden mode first; our guard then restores
    // the original terminal mode on both normal return and error.
    rpassword::read_password()
}
#[cfg(not(unix))]
pub fn prompt_secret(_prompt: &str) -> std::io::Result<String> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Secure terminal prompts require Unix",
    ))
}
