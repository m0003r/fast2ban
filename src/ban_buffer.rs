#[derive(Debug)]
pub(crate) struct RingBanBuffer {
    timestamps: Vec<Option<i64>>,
    last_index: usize,
    pub banned: bool,
    pub whitelisted: bool,
}

impl RingBanBuffer {
    pub(crate) fn new(ring_size: usize) -> RingBanBuffer {
        RingBanBuffer {
            timestamps: vec![None; ring_size],
            last_index: 0,
            banned: false,
            whitelisted: false,
        }
    }

    pub(crate) fn add_query(&mut self, ts: i64) -> Option<i64> {
        self.timestamps[self.last_index] = Some(ts);
        self.last_index = (self.last_index + 1) % self.timestamps.len();

        self.timestamps[self.last_index].map(|prev| prev - ts)
    }
}
