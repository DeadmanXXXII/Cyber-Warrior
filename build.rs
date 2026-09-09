// This app links against pnet's Windows packet-capture backend, which
// implicitly imports wpcap.dll and Packet.dll (from the Npcap SDK — see
// the "Install Npcap SDK" CI step). An *implicit* Windows import means the
// OS loader tries to resolve those DLLs the moment it starts the .exe, for
// every launch, whether or not Network Monitor is ever used. On a machine
// without the Npcap runtime installed (e.g. a clean Microsoft Store
// certification test image), that load-time resolution fails and Windows
// refuses to start the process at all — showing its own error dialog
// before a single line of our Rust code (including main()) runs. That is
// what produced the "Unusable Feature: an error is displayed at launch"
// certification failure.
//
// Fix: delay-load those two DLLs so the loader only resolves them the
// first time something in the binary actually calls into them, not at
// process start. That alone unblocks *launch*. To keep the app from
// crashing later when a user without Npcap opens Network Monitor, our own
// code checks for wpcap.dll with LoadLibraryEx before ever calling pnet
// (see modules/packet_monitor.rs::npcap_available()), so delay-load
// resolution failure is never actually triggered at runtime either.
fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    // /DELAYLOAD is an MSVC linker feature (via delayimp.lib); it isn't
    // meaningful for the GNU/mingw toolchain, so only apply it for the
    // windows-msvc target (what GitHub's windows-latest + rustup default
    // to).
    if target_os == "windows" && target_env == "msvc" {
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-arg=/DELAYLOAD:Packet.dll");
        println!("cargo:rustc-link-arg=delayimp.lib");
    }
}
