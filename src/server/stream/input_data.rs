pub enum InputData {
    Capped { data: Box<[u8]> },
    Uncapped(Vec<u8>),
}

impl InputData {
    fn capped(len: usize) -> Self {
        Self::Capped {
            data: vec![0u8; len].into_boxed_slice(),
        }
    }

    fn uncapped() -> Self {
        Self::Uncapped(Vec::new())
    }
}
