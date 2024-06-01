# HTTP-Parser
HTTP Parser in Rust

# Compiling
```bash
cargo build --release
```

# Usage
Print help
```bash
./target/release/http-parser --help
```

Print parse tree to stdio
```bash
./target/release/http-parser <file>
```

Store parse tree to JSON file
```bash
./target/release/http-parser <file> --json-path <path>
```
