use std::cell::RefCell;

pub struct SharedConnection {
    writer: Writer,
}

struct Writer {
    queue: RefCell<Vec<Vec<u8>>>,
}
