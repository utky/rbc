use log::info;
use std::time::{Duration, Instant};
use tokio::time::sleep;

pub async fn start() -> std::io::Result<()> {
    info!("start scheduler");
    loop {
        sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}
