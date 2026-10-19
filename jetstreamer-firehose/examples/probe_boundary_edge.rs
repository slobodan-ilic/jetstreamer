//! Read-only diagnostic: decode the first block in one successor CAR.
use jetstreamer_firehose::{epochs::fetch_epoch_stream, node_reader::NodeReader};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let epoch: u64 = std::env::args().nth(1).ok_or("expected epoch")?.parse()?;
    let client = jetstreamer_firehose::network::create_http_client();
    if std::env::args().nth(2).as_deref() == Some("--bounded-prefix") {
        // Diagnostic only: compare one bounded range with the ordinary reader's
        // open-ended request. Reject status/framing errors before CAR decoding.
        const LIMIT: usize = 1024 * 1024;
        let response = client
            .get(format!(
                "https://files.old-faithful.net/{epoch}/epoch-{epoch}.car"
            ))
            .header(reqwest::header::RANGE, format!("bytes=0-{}", LIMIT - 1))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await?
            .error_for_status()?;
        if response.status() != reqwest::StatusCode::PARTIAL_CONTENT
            || response.content_length() != Some(LIMIT as u64)
            || !response
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("bytes 0-1048575/"))
        {
            return Err("unexpected bounded CAR range response".into());
        }
        let bytes = response.bytes().await?;
        if bytes.len() != LIMIT {
            return Err("incomplete bounded CAR response".into());
        }
        let mut reader = jetstreamer_firehose::node::NodeReader::new(std::io::Cursor::new(bytes))?;
        reader.read_raw_header()?;
        for _ in 0..100_000 {
            let node = reader.next_parsed()?;
            if let Some(block) = node.get_node().get_block() {
                println!(
                    "bounded_bytes={LIMIT} epoch={epoch} parent={} slot={}",
                    block.meta.parent_slot, block.slot
                );
                return Ok(());
            }
        }
        return Err("first block exceeds diagnostic node bound".into());
    }
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let stream = fetch_epoch_stream(epoch, &client).await;
        let mut reader = NodeReader::new(stream);
        let header = reader.read_raw_header().await?;
        eprintln!("epoch={epoch} header_bytes={}", header.len());
        for _ in 0..100_000 {
            let node = reader.next_parsed().await?;
            if let Some(block) = node.get_node().get_block() {
                println!(
                    "epoch={epoch} items={} parent={} slot={}",
                    reader.get_item_index(),
                    block.meta.parent_slot,
                    block.slot
                );
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
        }
        Err("first block exceeds diagnostic node bound".into())
    })
    .await??;
    Ok(())
}
