//! Drive tarishsharingd from a shell, so end-to-end tests need no screen taps.
//!
//! The point is the tests nobody runs by hand: both protocols advertising at once,
//! a transfer cancelled mid-file, recovery after the daemon restarts. Each needs two
//! devices doing something at the same moment, which is exactly what a person with one
//! pair of hands cannot do reliably.
//!
//! Every command prints one line per fact, whitespace-separated, so a harness can parse it
//! with awk and a person can read it. Errors go to stderr and set a non-zero exit.

use binder::Strong;
use dev_tarish::aidl::dev::tarish::ITarishService::ITarishService;
use dev_tarish::aidl::dev::tarish::TarishPolicy::TarishPolicy;

const SERVICE: &str = "dev.tarish.ITarishService/default";

fn connect() -> Result<Strong<dyn ITarishService>, String> {
    binder::get_interface::<dyn ITarishService>(SERVICE)
        .map_err(|e| format!("cannot reach {SERVICE}: {e}\n\
             the daemon may be down (`adb shell ps -A | grep tarish`), or this build \
             lacks the userdebug sepolicy rule that lets a shell find the service"))
}

fn usage() -> ! {
    eprintln!(
        "tarishctl — drive the Tarish daemon (userdebug only)

  peers                       list discovered peers: id protocol name
  name [<new>]                get or set this device's name
  discoverable <on|off> [sec] advertise, or stop
  send <peer-id> <file>...    send over whatever transport suits the peer
  send-lan <peer-id> <file>.. force the Wi-Fi LAN path
  accept <transfer-id>        accept an incoming offer
  decline <transfer-id>       decline one
  pin <transfer-id> <code>    answer a PIN challenge
  cancel <transfer-id>        cancel a transfer in flight
  received                    list files this device has received
  refresh                     re-run discovery
  policy                      print the current policy
  policy pin <on|off>         require a PIN before sending, or do not
  policy mode <0|1|2|3>       set both protocols: off / contacts / everyone / ...

Ids are opaque; take them from `peers` and from the daemon log."
    );
    std::process::exit(2)
}

fn open_files(paths: &[String]) -> Result<(Vec<binder::ParcelFileDescriptor>, Vec<String>), String> {
    let mut fds = Vec::new();
    let mut names = Vec::new();
    for p in paths {
        let f = std::fs::File::open(p).map_err(|e| format!("{p}: {e}"))?;
        names.push(
            std::path::Path::new(p)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| p.clone()),
        );
        fds.push(binder::ParcelFileDescriptor::new(f));
    }
    Ok((fds, names))
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage()
    }
    let svc = connect()?;
    match args[0].as_str() {
        "peers" => {
            for p in svc.getPeers().map_err(|e| e.to_string())? {
                // protocol is the number the AIDL uses; the harness matches on it rather
                // than on a name that might be translated or reworded.
                println!("{} {} {}", p.id, p.protocol, p.name);
            }
        }
        "name" => match args.get(1) {
            Some(n) => svc.setDeviceName(n).map_err(|e| e.to_string())?,
            None => println!("{}", svc.getDeviceName().map_err(|e| e.to_string())?),
        },
        "discoverable" => {
            let on = matches!(args.get(1).map(String::as_str), Some("on"));
            let secs: i32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            svc.setDiscoverable(on, secs).map_err(|e| e.to_string())?;
        }
        "send" | "send-lan" => {
            let peer = args.get(1).ok_or("send needs a peer id")?;
            let paths = &args[2..];
            if paths.is_empty() {
                return Err("send needs at least one file".into());
            }
            let (fds, names) = open_files(paths)?;
            let id = if args[0] == "send-lan" {
                svc.sendFilesOnLan(peer, &fds, &names)
            } else {
                svc.sendFiles(peer, &fds, &names)
            }
            .map_err(|e| e.to_string())?;
            // The transfer id is the handle for accept/cancel, so it is the only output.
            println!("{id}");
        }
        "accept" | "decline" => {
            let id: i64 = args.get(1).ok_or("needs a transfer id")?.parse().map_err(|_| "bad id")?;
            svc.respondToOffer(id, args[0] == "accept").map_err(|e| e.to_string())?;
        }
        "pin" => {
            let id: i64 = args.get(1).ok_or("needs a transfer id")?.parse().map_err(|_| "bad id")?;
            let code = args.get(2).ok_or("needs a pin")?;
            println!("{}", svc.confirmTransferPin(id, code).map_err(|e| e.to_string())?);
        }
        "cancel" => {
            let id: i64 = args.get(1).ok_or("needs a transfer id")?.parse().map_err(|_| "bad id")?;
            svc.cancelTransfer(id).map_err(|e| e.to_string())?;
        }
        "received" => {
            for f in svc.getReceivedFiles().map_err(|e| e.to_string())? {
                println!("{f}");
            }
        }
        "refresh" => svc.refreshPeers().map_err(|e| e.to_string())?,
        // Testing a transfer end to end means answering the PIN, and a harness that
        // scrapes it out of logcat races the log. Turning the requirement off makes the
        // transport testable on its own; leaving it on is what a person gets.
        "policy" => {
            let mut p: TarishPolicy = Default::default();
            p.airdrop = 3;
            p.quickshare = 3;
            p.requireConfirmation = true;
            match (args.get(1).map(String::as_str), args.get(2).map(String::as_str)) {
                // NO READBACK. There is no getter on the interface, and printing the
                // defaults this command was about to send would be inventing an answer:
                // it read "confirm=true" immediately after successfully setting it false.
                // The daemon logs the real thing when it changes -- grep its log for
                // "policy: airdrop=... confirm=..." -- so say that instead of guessing.
                (None, _) => {
                    return Err("no getter on the interface; read the daemon's log line \
                                \"policy: airdrop=.. quickshare=.. confirm=..\" instead"
                        .into());
                }
                (Some("pin"), Some(v)) => p.requireConfirmation = v == "on",
                (Some("mode"), Some(v)) => {
                    let m: i32 = v.parse().map_err(|_| "mode takes a number")?;
                    p.airdrop = m;
                    p.quickshare = m;
                }
                _ => usage(),
            }
            svc.setPolicy(&p).map_err(|e| e.to_string())?;
        }
        _ => usage(),
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("tarishctl: {e}");
        std::process::exit(1);
    }
}
