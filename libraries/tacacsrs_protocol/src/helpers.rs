use std::io::{Cursor, Read};
use anyhow::Context;

pub fn read_bytes(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<u8>, anyhow::Error> {
    // The packet data length bounds the cursor position. The length fits in usize.
    #[allow(clippy::cast_possible_truncation)]
    let remaining_buffer = cursor.get_ref().len() - cursor.position() as usize;
    if remaining_buffer < len {
        return Err(anyhow::Error::msg("cannot read bytes: the remaining buffer is too short"));
    }

    let mut buffer = vec![0; len];
    cursor
        .read_exact(&mut buffer)
        .with_context(|| format!("failed to read {len} bytes from the cursor"))?;

    Ok(buffer)
}

pub fn read_string(cursor: &mut Cursor<&[u8]>, len: usize) -> Result<String, anyhow::Error> {
    // The packet data length bounds the cursor position. The length fits in usize.
    #[allow(clippy::cast_possible_truncation)]
    let remaining_buffer = cursor.get_ref().len() - cursor.position() as usize;
    if remaining_buffer < len {
        return Err(anyhow::Error::msg(
            "cannot read the string: the remaining buffer is too short",
        ));
    }

    let mut buffer = vec![0; len];
    cursor
        .read_exact(&mut buffer)
        .with_context(|| format!("failed to read {len} bytes from the cursor"))?;

    let string = String::from_utf8(buffer).with_context(|| "data is not a valid UTF-8 string")?;

    Ok(string)
}
