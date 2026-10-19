//! Read-only diagnostic: decode the first block in one successor CAR.
use jetstreamer_firehose::{epochs::fetch_epoch_stream, node_reader::NodeReader};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let epoch: u64 = std::env::args().nth(1).ok_or("expected epoch")?.parse()?;
    let client = jetstreamer_firehose::network::create_http_client();
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
