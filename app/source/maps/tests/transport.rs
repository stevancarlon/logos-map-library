// SPDX-License-Identifier: MIT OR Apache-2.0
use logos_map_distribution::{parse_md5_sidecar, transport::StorageNode};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
};
fn server(body: &'static [u8]) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/api/storage/v1", listener.local_addr().unwrap());
    let task = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut byte = [0; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            socket.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() < 8192);
        }
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .unwrap();
        socket.write_all(body).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (url, task)
}
#[test]
fn hosted_download_uses_only_storage_and_checks_bytes() {
    let (url, task) = server(b"abc");
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("map.pbf");
    let md5 = parse_md5_sidecar("900150983cd24fb0d6963f7d28e17f72").unwrap();
    let content = StorageNode::new(&url)
        .unwrap()
        .download_verified("bafyFixture", md5, 3, &destination)
        .unwrap();
    assert_eq!(content.bytes, 3);
    assert_eq!(std::fs::read(destination).unwrap(), b"abc");
    assert!(
        task.join()
            .unwrap()
            .starts_with("GET /api/storage/v1/data/bafyFixture/network/stream ")
    );
}
#[test]
fn corrupted_download_does_not_leave_destination() {
    let (url, task) = server(b"corrupted");
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("map.pbf");
    let md5 = parse_md5_sidecar("900150983cd24fb0d6963f7d28e17f72").unwrap();
    assert!(
        StorageNode::new(&url)
            .unwrap()
            .download_verified("bafyFixture", md5, 20, &destination)
            .is_err()
    );
    assert!(!destination.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    task.join().unwrap();
}
#[test]
fn existing_map_is_never_overwritten() {
    let url = "http://127.0.0.1:1"; // Existing destination must fail before networking.
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("map.pbf");
    std::fs::write(&destination, b"existing").unwrap();
    let md5 = parse_md5_sidecar("900150983cd24fb0d6963f7d28e17f72").unwrap();
    let error = StorageNode::new(url)
        .unwrap()
        .download_verified("bafyFixture", md5, 3, &destination)
        .unwrap_err();
    assert!(
        matches!(error, logos_map_distribution::Error::Invalid(ref message) if message.contains("Destination already exists"))
    );
    assert_eq!(std::fs::read(&destination).unwrap(), b"existing");
}

#[test]
fn transient_upload_rewinds_the_verified_snapshot_not_the_changed_input() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/api/storage/v1", listener.local_addr().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.bin");
    std::fs::write(&input, b"abc").unwrap();
    let changed_input = input.clone();
    let task = thread::spawn(move || {
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut headers = Vec::new();
            let mut byte = [0];
            while !headers.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
            }
            let headers = String::from_utf8(headers).unwrap();
            assert!(headers.starts_with("POST /api/storage/v1/data?advertise=true "));
            let length = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let mut body = vec![0; length];
            socket.read_exact(&mut body).unwrap();
            assert_eq!(body, b"abc");
            if attempt == 0 {
                std::fs::write(&changed_input, b"changed after verification").unwrap();
                socket.write_all(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            } else {
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nbafyFixture").unwrap();
            }
        }
    });
    let md5 = parse_md5_sidecar("900150983cd24fb0d6963f7d28e17f72").unwrap();
    let result = StorageNode::new(&url)
        .unwrap()
        .upload_verified(&input, md5, 3, dir.path())
        .unwrap();
    assert_eq!(result.cid, "bafyFixture");
    assert_eq!(result.content.bytes, 3);
    task.join().unwrap();
}

#[test]
fn registered_download_checks_sha_and_exact_length_before_publishing() {
    let snapshot = logos_map_registry::Snapshot {
        region: "africa/ethiopia".into(),
        parent: None,
        level: "country".into(),
        cid: "bafyFixture".into(),
        source_url: "https://download.geofabrik.de/africa/ethiopia-latest.osm.pbf".into(),
        checksum: parse_md5_sidecar("900150983cd24fb0d6963f7d28e17f72").unwrap(),
        sha256: hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap()
            .try_into()
            .unwrap(),
        bytes: 3,
        version: 20261008,
        hosted: true,
    };
    let directory = tempfile::tempdir().unwrap();
    for (index, wrong_sha, wrong_size) in [(0, false, false), (1, true, false), (2, false, true)] {
        let (url, task) = server(b"abc");
        let mut record = snapshot.clone();
        if wrong_sha {
            record.sha256 = [1; 32];
        }
        if wrong_size {
            record.bytes = 4;
        }
        let path = directory.path().join(format!("{index}.pbf"));
        let result = StorageNode::new(&url)
            .unwrap()
            .download_snapshot(&record, 4, &path);
        if index == 0 {
            assert!(result.is_ok());
            assert_eq!(std::fs::read(&path).unwrap(), b"abc");
        } else {
            assert!(result.is_err());
            assert!(!path.exists());
        }
        task.join().unwrap();
    }
    let node = StorageNode::new("http://127.0.0.1:1").unwrap();
    assert!(matches!(
        node.download_snapshot(&snapshot, 2, &directory.path().join("oversized")),
        Err(logos_map_distribution::Error::Size)
    ));
}

// Exercise the actual HTTP retry loop, including exhaustion and permanent errors.
fn failing_upload(status: u16, expected_requests: usize) -> (String, Vec<std::time::Instant>) {
    use std::time::{Duration, Instant};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/api/storage/v1", listener.local_addr().unwrap());
    let task = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut arrivals = Vec::new();
        while arrivals.len() < expected_requests {
            let mut socket = match listener.accept() {
                Ok((socket, _)) => socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "Upload requests did not arrive");
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            arrivals.push(Instant::now());
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut headers = Vec::new();
            let mut byte = [0];
            while !headers.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
                assert!(headers.len() < 8192);
            }
            let mut body = [0; 3];
            socket.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"abc");
            write!(
                socket,
                "HTTP/1.1 {status} Failed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        }
        arrivals
    });
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("input.pbf");
    std::fs::write(&input, b"abc").unwrap();
    let md5 = parse_md5_sidecar("900150983cd24fb0d6963f7d28e17f72").unwrap();
    let error = StorageNode::new(&url)
        .unwrap()
        .upload_verified(&input, md5, 3, directory.path())
        .unwrap_err();
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    (error.to_string(), task.join().unwrap())
}

#[test]
fn upload_exhaustion_has_four_attempts_with_exponential_backoff() {
    let (error, arrivals) = failing_upload(503, 4);
    assert!(error.contains("attempts: 4"), "{error}");
    for (gap, minimum_ms) in arrivals.windows(2).zip([950, 1950, 3950]) {
        assert!(gap[1].duration_since(gap[0]) >= std::time::Duration::from_millis(minimum_ms));
    }
}

#[test]
fn permanent_upload_error_stops_after_one_attempt() {
    let (error, arrivals) = failing_upload(403, 1);
    assert!(error.contains("attempts: 1"), "{error}");
    assert_eq!(arrivals.len(), 1);
}

#[test]
fn import_checksum_failure_does_not_contact_storage() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("wrong.pbf");
    std::fs::write(&input, b"corrupted").unwrap();
    let md5 = parse_md5_sidecar("900150983cd24fb0d6963f7d28e17f72").unwrap();
    let node = StorageNode::new(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
    let error = node
        .upload_verified(&input, md5, 20, directory.path())
        .unwrap_err();
    assert!(matches!(error, logos_map_distribution::Error::Checksum));
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
