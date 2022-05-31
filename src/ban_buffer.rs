#[derive(Debug)]
pub(crate) struct RingBanBuffer {
    last_queries: Vec<Option<i64>>,
    last_query_index: usize,
    pub banned: bool
}

impl RingBanBuffer {
    pub(crate) fn new(ring_size: usize) -> RingBanBuffer {
        RingBanBuffer {
            last_queries: vec![None; ring_size],
            last_query_index: 0,
            banned: false
        }
    }

    pub(crate) fn add_query(&mut self, query: i64) -> Option<i64> {
        self.last_queries[self.last_query_index] = Some(query);
        self.last_query_index = (self.last_query_index + 1) % self.last_queries.len();

        if let Some(prev) = self.last_queries[self.last_query_index] {
            Some(prev - query)
        } else {
            None
        }
    }
}