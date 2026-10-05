pub fn log_to_file(
    file_path: &str,
    text: &str,
) {
    use std::fs::OpenOptions;
    use std::io::Write;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(file_path)
        .expect("Failed to open file");

    writeln!(file, "{}", text).expect("Failed to write to file");
}
