use std::time::{SystemTime, UNIX_EPOCH};

// Define the version information with compile date and time
// This is used to display information when the DLL is loaded
fn get_fish_main_version(pkg_version: &str, build_date: &str, build_time: &str) -> String {
    format!(
        "{}compiled {} {} ***",
        format!("*** FiSH {} *** by [GuY] *** fish_11.dll ", pkg_version),
        build_date,
        build_time
    )
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Debug output
    println!("cargo:warning=Generating build information for FiSH 11");

    // Manually set the build date and time
    let now = SystemTime::now();
    let since_epoch = now.duration_since(UNIX_EPOCH).expect("Time went backwards");

    // Format current date and time as fallback
    let seconds = since_epoch.as_secs();
    let secs = seconds % 60;
    let minutes = (seconds / 60) % 60;
    let hours = (seconds / 3600) % 24;
    let days = (seconds / 86400) % 30;
    let months = ((seconds / 86400) / 30) % 12;
    let years = 1970 + (seconds / 86400) / 365;

    // Set fallback values
    let fallback_date = format!("{:04}-{:02}-{:02}", years, months + 1, days + 1);
    let fallback_time = format!("{:02}:{:02}:{:02}", hours, minutes, secs);

    // Get the package version
    let pkg_version = std::env::var("CARGO_PKG_VERSION").unwrap();

    // Calculate the version string
    let version_string = get_fish_main_version(&pkg_version, &fallback_date, &fallback_time);
    println!("cargo:warning=Version info: {}", version_string);

    // Set these as cargo variables that will be accessible via env! macro
    println!("cargo:rustc-env=FISH_FALLBACK_DATE={}", fallback_date);
    println!("cargo:rustc-env=FISH_FALLBACK_TIME={}", fallback_time);
    println!("cargo:rustc-env=FISH_MAIN_VERSION={}", version_string);
}
