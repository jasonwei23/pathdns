use anyhow::{anyhow, Result};

struct ResponseBuilder {
    buf: Vec<u8>,
}

impl ResponseBuilder {
    fn from_query(query: &[u8], question_end: usize) -> Result<Self> {
        if query.len() < 12 || question_end > query.len() {
            return Err(anyhow!("invalid dns query"));
        }
        let mut buf = query[..question_end].to_vec();
        buf[2] = 0x80 | (query[2] & 0x01); // QR=1, RD=copied; clear AA, TC, OPCODE
        buf[3] = 0x00; // RA=0, AD=0, CD=0, RCODE=0
        buf[4] = 0x00;
        buf[5] = 0x01; // QDCOUNT=1
        buf[6] = 0x00;
        buf[7] = 0x00; // ANCOUNT=0
        buf[8] = 0x00;
        buf[9] = 0x00; // NSCOUNT=0
        buf[10] = 0x00;
        buf[11] = 0x00; // ARCOUNT=0
        Ok(Self { buf })
    }

    fn set_ra(&mut self) -> &mut Self {
        self.buf[3] |= 0x80;
        self
    }

    fn set_rcode(&mut self, rcode: u8) -> &mut Self {
        self.buf[3] = (self.buf[3] & 0xf0) | (rcode & 0x0f);
        self
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// NOERROR response with no answer records (used for qtype-filtered queries).
pub fn empty_reply(query: &[u8], question_end: usize) -> Result<Vec<u8>> {
    Ok(ResponseBuilder::from_query(query, question_end)?.finish())
}

/// SERVFAIL response: RCODE=2, RA=1.
pub fn servfail_reply(query: &[u8], question_end: usize) -> Result<Vec<u8>> {
    let mut b = ResponseBuilder::from_query(query, question_end)?;
    b.set_ra().set_rcode(2);
    Ok(b.finish())
}
