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
  app ping                    is the app's debug bridge listening?
  app peers                   peers as the APP sees them (psm, BLE address)
  app send <peer-id> <file>   send VIA THE APP: Bluetooth, and Wi-Fi Direct upgrade
  policy                      print the current policy
  policy pin <on|off>         require the sender to type the receiver's PIN
  policy confirm <on|off>     ask before accepting an incoming transfer
  policy mode <0|1|2|3>       both protocols: 0 off, 1 receive, 2 send, 3 both
  policy airdrop <0|1|2|3>    AirDrop only, leaving Quick Share alone
  policy quickshare <0..3>    Quick Share only, leaving AirDrop alone

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

        // THE TRANSPORTS THE DAEMON DOES NOT OWN.
        //
        // sendFilesOnSocket takes a Bluetooth socket and provideWifiDirectGroup takes a
        // P2P group, and both are framework API a native daemon cannot reach -- so
        // Bluetooth and Wi-Fi Direct were SKIP in every end-to-end run and had never been
        // exercised against real hardware. The app listens on a local socket for exactly
        // this, on a debuggable build only.
        //
        // `app send` off-network is the valuable one: QuickShareSender tries the LAN,
        // falls through to Bluetooth, and the daemon may then ask to upgrade to Wi-Fi
        // Direct with the app answering. One command drives the bootstrap AND the upgrade.
        "app" => {
            if args.len() < 2 {
                return Err("usage: app <ping|peers|send <peer-id> <path>>".into());
            }
            println!("{}", app_command(&args[1..].join(" "))?);
        }
        // Testing a transfer end to end means answering the PIN, and a harness that
        // scrapes it out of logcat races the log, so `policy pin off` exists to make the
        // transport testable on its own; leaving it on is what a person gets.
        "policy" => {
            // READ, MODIFY, WRITE -- never build a policy from defaults.
            //
            // setPolicy replaces the WHOLE parcelable, so a subcommand that means to
            // touch one field has to carry every other field forward or it silently
            // rewrites them. This used to start from Default::default() with airdrop and
            // quickshare forced to MODE_BOTH, which meant `policy pin off` -- whose
            // entire job is the PIN -- ALSO TURNED AIRDROP ON, and cleared the device
            // name and every *Managed flag on the way past.
            //
            // On a device whose radio cannot hold AWDL and Wi-Fi at once that takes wlan0
            // down. Quick Share then has no LAN route, sendFilesOnLan returns 0, and the
            // harness reports "no offer reached the receiver" -- six failing rows blaming
            // the peer for damage done by the tool that was supposed to be observing it.
            let mut p = svc.getPolicy().map_err(|e| e.to_string())?;
            let mode = |v: &str| -> Result<i32, String> {
                match v.parse::<i32>() {
                    Ok(m) if (0..=3).contains(&m) => Ok(m),
                    _ => Err("mode takes 0 (off), 1 (receive), 2 (send) or 3 (both)".into()),
                }
            };
            match (args.get(1).map(String::as_str), args.get(2).map(String::as_str)) {
                // A REAL readback. getPolicy() has always existed on the interface; an
                // earlier comment here claimed it did not and printed the defaults it was
                // about to send instead, which reported "confirm=true" immediately after
                // successfully setting it false.
                (None, _) => {
                    println!(
                        "airdrop={} quickshare={} confirm={} pin={} name={:?}",
                        p.airdrop,
                        p.quickshare,
                        p.requireConfirmation,
                        p.requirePin,
                        p.deviceName
                    );
                    println!(
                        "managed airdrop={} quickshare={} confirm={} pin={} name={}",
                        p.airdropManaged,
                        p.quickshareManaged,
                        p.requireConfirmationManaged,
                        p.requirePinManaged,
                        p.deviceNameManaged
                    );
                    return Ok(());
                }
                // requirePin is the PIN the SENDER types. requireConfirmation is the
                // receiver's accept prompt -- a different question, so a different
                // subcommand. `pin` used to set requireConfirmation, and only appeared to
                // work because requirePin happened to be false in Default::default().
                (Some("pin"), Some(v)) => p.requirePin = v == "on",
                (Some("confirm"), Some(v)) => p.requireConfirmation = v == "on",
                (Some("mode"), Some(v)) => {
                    let m = mode(v)?;
                    p.airdrop = m;
                    p.quickshare = m;
                }
                // Per protocol, because the interesting case is exactly one of them off:
                // an exclusive radio has to drop AWDL for Quick Share to have a transport
                // at all, and "both to the same mode" cannot express that.
                (Some("airdrop"), Some(v)) => p.airdrop = mode(v)?,
                (Some("quickshare"), Some(v)) => p.quickshare = mode(v)?,
                _ => usage(),
            }
            svc.setPolicy(&p).map_err(|e| e.to_string())?;
        }
        _ => usage(),
    }
    Ok(())
}

/// Send one line to the app's debug bridge and return its reply.
///
/// Abstract namespace (a leading NUL in sun_path), so there is no filesystem path to label
/// or clean up. std can only address these behind an unstable feature, so the connect goes
/// through libc.
fn app_command(line: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::os::unix::io::FromRawFd;

    const NAME: &[u8] = b"tarish-debug";
    // SAFETY: a zeroed sockaddr_un is valid, and NAME is written inside sun_path below.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if NAME.len() + 1 > addr.sun_path.len() {
        return Err("socket name too long".into());
    }
    for (i, b) in NAME.iter().enumerate() {
        // sun_path[0] stays NUL: that leading zero is what makes it abstract.
        addr.sun_path[i + 1] = *b as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + NAME.len()) as libc::socklen_t;

    // SAFETY: fd is closed by the UnixStream taking ownership, or explicitly on error.
    let mut stream = unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err("socket() failed".into());
        }
        if libc::connect(fd, &addr as *const _ as *const libc::sockaddr, len) != 0 {
            libc::close(fd);
            return Err("the app is not listening on @tarish-debug — is it running, and \
                        is this a debuggable build?"
                .into());
        }
        std::os::unix::net::UnixStream::from_raw_fd(fd)
    };

    stream.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    stream.write_all(b"\n").map_err(|e| e.to_string())?;
    // The app answers one line and closes, so read to end rather than guessing a length.
    let mut out = String::new();
    stream.read_to_string(&mut out).map_err(|e| e.to_string())?;
    Ok(out.trim_end().to_string())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("tarishctl: {e}");
        std::process::exit(1);
    }
}
