use std::env;
use std::io;

fn main() -> io::Result<()> {
    // Only run this build script when compiling for Windows.
    // This is necessary because `winresource` only works on Windows targets.
    if env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let mut res = winresource::WindowsResource::new();

        // This line specifies the path to the icon file to be embedded into the .exe
        // The path is relative to the project root (where Cargo.toml is).
        res.set_icon("assets/aegis2.ico");

        // Compile the resource file
        res.compile()?;
    }
    Ok(())
}
