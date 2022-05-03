use tools::start_server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    start_server().await
}
