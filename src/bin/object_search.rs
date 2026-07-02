use std::process::ExitCode;

use clap::Parser;
use ue5_dumper::{mem::ProcessHandle, scanner, ue};

#[derive(Parser, Debug)]
#[command(name = "object-search")]
struct Args {
    #[arg(short, long)]
    process: String,
    #[arg(required = true)]
    needles: Vec<String>,
    #[arg(long, default_value_t = 300)]
    limit: usize,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let Some(proc) = ProcessHandle::attach(&args.process) else {
        eprintln!("process not found: {}", args.process);
        return ExitCode::from(1);
    };
    println!("pid={} base={:#x}", proc.pid, proc.base);
    let Some(scan) = scanner::scan(&proc) else {
        eprintln!("scan failed");
        return ExitCode::from(1);
    };
    let Some(mut names) = ue::fname::FNamePool::with_addr(&proc, scan.gnames) else {
        eprintln!("fname failed");
        return ExitCode::from(1);
    };
    let Some(gobjects) = ue::objects::GObjects::with_addr(&proc, scan.gobjects, scan.layout) else {
        eprintln!("gobjects failed");
        return ExitCode::from(1);
    };
    let needles = args
        .needles
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut shown = 0usize;
    for obj in &gobjects.objects {
        let full = gobjects.full_name(&proc, &mut names, obj.addr).unwrap_or_default();
        let full_l = full.to_ascii_lowercase();
        if !needles.iter().any(|n| full_l.contains(n)) {
            continue;
        }
        let class = gobjects
            .full_name(&proc, &mut names, obj.class_addr)
            .unwrap_or_default();
        println!("addr={:#x} class={:#x} class_name={} full={}", obj.addr, obj.class_addr, class, full);
        shown += 1;
        if shown >= args.limit {
            break;
        }
    }
    println!("shown={shown}");
    ExitCode::SUCCESS
}
