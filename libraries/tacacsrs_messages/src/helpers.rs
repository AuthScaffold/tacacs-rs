use std::io::{Cursor, Read};
use anyhow::Context;


pub fn read_string(cursor : &mut Cursor<&[u8]>, len: usize) -> Result<String, anyhow::Error> {
    let remaining_buffer = cursor.get_ref().len() - cursor.position() as usize;
    if remaining_buffer < len {
        return Err(anyhow::Error::msg("Not enough data to read string. Remaining buffer too short"));
    }

    let mut buffer = vec![0; len];
    cursor.read_exact(&mut buffer).with_context(|| format!("Unable to read {} bytes from cursor", len))?;

    let string = String::from_utf8(buffer).with_context(|| "Unable to read data into UTF8 formatted string")?;

    Ok(string)
}