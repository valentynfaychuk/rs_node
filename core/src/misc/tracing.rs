pub fn init_logging() {
    // Minimal, dependency-light logging initialization.
    // Prefer not to fail if a subscriber is already set elsewhere.
    let _ = tracing_subscriber::fmt::try_init();

    // Install a panic hook that reports to stderr without requiring tracing macros.
    std::panic::set_hook(Box::new(|pi| {
        eprintln!("panic: {}", pi);
    }));
}
