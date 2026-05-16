fn main() {
    // Tell Cargo to recompile (and re-embed) when any frontend file changes
    println!("cargo:rerun-if-changed=index.html");
    println!("cargo:rerun-if-changed=app.js");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    tauri_build::build()
}
