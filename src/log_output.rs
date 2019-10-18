use std::cell::RefCell;

thread_local! {
    pub static LOG_BUFFER: RefCell<Vec<u8>> = RefCell::new(vec![]);
}

pub struct LogOutput;

impl std::io::Write for LogOutput {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        LOG_BUFFER.with(|b| {
            b.borrow_mut().extend_from_slice(buf);

            // only actually write out if a newline is received
            if b.borrow().last().cloned() == Some('\n' as u8) {
                // remove newline
                b.borrow_mut().pop();

                log::info!("{}", String::from_utf8_lossy(&b.borrow()));

                // clear the buffer
                b.borrow_mut().clear();
            }
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
