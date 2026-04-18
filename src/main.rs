mod mem;
mod ue;
mod scanner;
mod codegen;

use clap::Parser;
use mem::ProcessHandle;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Serialize)]
struct SdkDump {
    num_objects: usize,
    classes: Vec<ue::props::ClassDump>,
    enums: Vec<ue::props::EnumDump>,
}

/// Unreal Engine 5 SDK dumper for Linux.
///
/// Attaches to a running UE5 game via process_vm_readv(2), scans for GNames,
/// GObjects, and GWorld, then emits dumps in the requested formats.
#[derive(Parser, Debug)]
#[command(name = "ue5-dumper", version, about, long_about = None)]
struct Args {
    /// Substring of the target process cmdline.
    ///
    /// Matched against /proc/<pid>/cmdline. For Wine/Proton games use the
    /// Windows .exe name (e.g. "MyGame-Win64-Shipping.exe").
    #[arg(short, long)]
    process: String,

    /// Only dump classes/structs whose name or full path contains this pattern.
    #[arg(short, long)]
    filter: Option<String>,

    /// Emit sdk.rs (Rust #[repr(C)] struct bindings).
    #[arg(long)]
    rust: bool,

    /// Emit chain.rs (GWorld -> local player pawn pointer-chain offsets).
    #[arg(long)]
    chain: bool,

    /// JSON output path.
    #[arg(long, default_value = "sdk_dump.json")]
    json_out: PathBuf,

    /// Rust bindings output path (only used with --rust).
    #[arg(long, default_value = "sdk.rs")]
    rust_out: PathBuf,

    /// Chain offsets output path (only used with --chain).
    #[arg(long, default_value = "chain.rs")]
    chain_out: PathBuf,

    /// Skip writing the JSON dump (useful if you only want --rust or --chain output).
    #[arg(long)]
    no_json: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    println!("[*] Attaching to process \"{}\"...", args.process);
    let proc = match ProcessHandle::attach(&args.process) {
        Some(p) => p,
        None => {
            eprintln!("[!] Could not find a process matching \"{}\". Is it running?", args.process);
            return ExitCode::from(1);
        }
    };
    println!("[+] PID: {}, Base: {:#X}", proc.pid, proc.base);

    println!("[*] Scanning for UE5 globals...");
    let scan = match scanner::scan(&proc) {
        Some(s) => s,
        None => {
            eprintln!("[!] Scanner could not locate GNames/GObjects/GWorld.");
            eprintln!("    This usually means the target is not a UE5 game, or its");
            eprintln!("    engine variant uses layouts outside what this dumper handles.");
            return ExitCode::from(1);
        }
    };
    let (gn_off, go_off, gw_off) = scan.offsets(proc.base);
    println!("[+] Scan complete:");
    println!("    GNames:   base + {gn_off:#X}");
    println!("    GObjects: base + {go_off:#X}");
    println!("    GWorld:   base + {gw_off:#X}");

    println!("[*] Reading FNamePool...");
    let mut names = match ue::fname::FNamePool::with_addr(&proc, scan.gnames) {
        Some(n) => n,
        None => {
            eprintln!("[!] Failed to initialize FNamePool");
            return ExitCode::from(1);
        }
    };
    if !names.validate(&proc) {
        eprintln!("[!] FNamePool validation failed");
        return ExitCode::from(1);
    }

    println!("[*] Reading GObjects...");
    let gobjects = match ue::objects::GObjects::with_addr(&proc, scan.gobjects) {
        Some(g) => g,
        None => {
            eprintln!("[!] Failed to read GObjects");
            return ExitCode::from(1);
        }
    };
    gobjects.validate(&proc, &mut names);

    println!("[*] Walking classes and properties...");
    let classes = ue::props::dump_classes(&proc, &mut names, &gobjects, args.filter.as_deref());

    println!("[*] Walking enums...");
    let enums = ue::props::dump_enums(&proc, &mut names, &gobjects, args.filter.as_deref());

    let dump = SdkDump {
        num_objects: gobjects.objects.len(),
        classes,
        enums,
    };

    let mut had_write_error = false;

    if !args.no_json {
        match serde_json::to_string_pretty(&dump) {
            Ok(json) => match fs::write(&args.json_out, &json) {
                Ok(()) => println!("[+] Wrote {} bytes to {}", json.len(), args.json_out.display()),
                Err(e) => {
                    eprintln!("[!] Failed to write {}: {e}", args.json_out.display());
                    had_write_error = true;
                }
            },
            Err(e) => {
                eprintln!("[!] JSON serialization failed: {e}");
                had_write_error = true;
            }
        }
    }

    if args.rust {
        let content = codegen::generate_rust(&dump.classes, &dump.enums, Some(&scan), proc.base);
        match fs::write(&args.rust_out, &content) {
            Ok(()) => println!("[+] Wrote {} bytes to {}", content.len(), args.rust_out.display()),
            Err(e) => {
                eprintln!("[!] Failed to write {}: {e}", args.rust_out.display());
                had_write_error = true;
            }
        }
    }

    if args.chain {
        let content = codegen::generate_chain(&dump.classes, gw_off);
        match fs::write(&args.chain_out, &content) {
            Ok(()) => println!("[+] Wrote {} bytes to {}", content.len(), args.chain_out.display()),
            Err(e) => {
                eprintln!("[!] Failed to write {}: {e}", args.chain_out.display());
                had_write_error = true;
            }
        }
    }

    if had_write_error {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
