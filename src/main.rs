#[tokio::main]
async fn main() {
    if let Err(error) = foxhole::cli::run_from_env().await {
        eprintln!(
            "[cli] error: {}",
            foxhole::terminal_safe(&error.to_string())
        );
        std::process::exit(1);
    }
}
