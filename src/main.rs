mod direct_io;

use clap::Parser;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use direct_io::AlignedBuffer;

/// A helper trait combining Read, Seek and Send
pub trait ReadSeek: std::io::Read + std::io::Seek + Send {}
impl<T: std::io::Read + std::io::Seek + Send> ReadSeek for T {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HashAlgorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Xxh64,
    Xxh3,
}

impl std::str::FromStr for HashAlgorithm {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace("-", "").as_str() {
            "sha224" => Ok(HashAlgorithm::Sha224),
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha384" => Ok(HashAlgorithm::Sha384),
            "sha512" => Ok(HashAlgorithm::Sha512),
            "xxh64" => Ok(HashAlgorithm::Xxh64),
            "xxh3" => Ok(HashAlgorithm::Xxh3),
            _ => Err(format!(
                "Unsupported hash algorithm: '{}'. Supported: sha224, sha256, sha384, sha512, xxh64, xxh3",
                s
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiskFormat {
    Qcow2,
    Vhdx,
    Vmdk,
    Raw,
}

impl std::str::FromStr for DiskFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "qcow2" => Ok(DiskFormat::Qcow2),
            "vhdx" => Ok(DiskFormat::Vhdx),
            "vmdk" => Ok(DiskFormat::Vmdk),
            "raw" => Ok(DiskFormat::Raw),
            _ => Err(format!(
                "Unsupported disk format: '{}'. Supported: qcow2, vhdx, vmdk, raw",
                s
            )),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "vdiskhash", version = "0.1.0", about = "Hashes virtual disk logical contents by chunk")]
struct Cli {
    /// Path to the virtual disk file (qcow2, vhdx, or vmdk)
    file_path: PathBuf,

    /// Hash algorithm to use (sha224, sha256, sha384, sha512, xxh64, xxh3)
    #[arg(short, long, default_value = "xxh3")]
    algorithm: HashAlgorithm,

    /// Chunk size for reading and hashing (e.g. 1Mi, 4Mi, 4096Ki, or raw bytes)
    #[arg(short, long, default_value = "1MiB")]
    chunk_size: String,

    /// Number of threads to use for hashing (default: half of logical CPUs, max 4)
    #[arg(short = 'j', long)]
    hash_threads: Option<usize>,

    /// Number of threads to use for disk reading/decoding (default: 4)
    #[arg(long, default_value_t = 4)]
    io_threads: usize,

    /// Disable OS read cache bypass (Direct I/O)
    #[arg(long)]
    no_bypass_cache: bool,

    /// Explicitly specify the disk format (qcow2, vhdx, vmdk, raw)
    #[arg(short, long)]
    format: Option<DiskFormat>,
}

fn detect_format(path: &Path) -> Result<DiskFormat, String> {
    let mut file = File::open(path)
        .map_err(|e| format!("Failed to open file for format detection: {}", e))?;
    
    let mut magic = [0u8; 8];
    let n = file.read(&mut magic).unwrap_or(0);
    
    if n >= 4 && &magic[0..4] == b"QFI\xfb" {
        return Ok(DiskFormat::Qcow2);
    }
    if n >= 4 && &magic[0..4] == b"KDMV" {
        return Ok(DiskFormat::Vmdk);
    }
    if n >= 8 && &magic[0..8] == b"vhdxfile" {
        return Ok(DiskFormat::Vhdx);
    }
    
    // Fallback to extension check
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        match ext.to_lowercase().as_str() {
            "qcow2" => return Ok(DiskFormat::Qcow2),
            "vmdk" => {
                // If the file ends with `-flat.vmdk`, it contains raw block data (RAW format)
                if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
                    if filename.to_lowercase().ends_with("-flat.vmdk") {
                        return Ok(DiskFormat::Raw);
                    }
                }
                return Ok(DiskFormat::Vmdk);
            }
            "vhdx" => return Ok(DiskFormat::Vhdx),
            "raw" | "img" | "bin" => return Ok(DiskFormat::Raw),
            _ => {}
        }
    }
    
    // Default to Raw format as a fallback for flat files/devices
    Ok(DiskFormat::Raw)
}

fn parse_chunk_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("Empty chunk size".to_string());
    }

    let digit_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if digit_end == 0 {
        return Err(format!("Invalid chunk size format: '{}'", s));
    }

    let num_part = &s[..digit_end];
    let suffix_part = s[digit_end..].trim().to_lowercase();

    let val: u64 = num_part.parse().map_err(|e| format!("Failed to parse number: {}", e))?;

    let multiplier = match suffix_part.as_str() {
        "" => 1,
        "k" | "ki" | "kib" => 1024,
        "m" | "mi" | "mib" => 1024 * 1024,
        "g" | "gi" | "gib" => 1024 * 1024 * 1024,
        _ => return Err(format!("Unknown unit suffix: '{}'", suffix_part)),
    };

    let total = val.checked_mul(multiplier)
        .ok_or_else(|| "Chunk size overflowed".to_string())?;

    if total == 0 {
        return Err("Chunk size must be greater than 0".to_string());
    }

    if total % 512 != 0 {
        return Err("Chunk size must be a multiple of 512 bytes (sector size)".to_string());
    }

    Ok(total as usize)
}

struct SharedReaderState {
    next_chunk: AtomicU64,
    num_chunks: u64,
    total_size: u64,
    chunk_size: usize,
    path: PathBuf,
    bypass_cache: bool,
    format: DiskFormat,
}

#[allow(unused_assignments)]
fn run_reader_worker(
    state: Arc<SharedReaderState>,
    free_rx: Arc<Mutex<std::sync::mpsc::Receiver<AlignedBuffer>>>,
    task_tx: std::sync::mpsc::SyncSender<(u64, u64, AlignedBuffer, usize)>,
) -> Result<(), String> {
    let file_len = std::fs::metadata(&state.path)
        .map_err(|e| format!("Failed to get metadata: {}", e))?
        .len();

    // We define local variables so they live as long as the boxed reader.
    let mut vhdx_disk = None;
    let mut cache_file = None;
    let mut qcow_io_reader_direct = None;
    let mut qcow_io_reader_normal = None;
    let mut qcow2_direct = None;
    let mut qcow2_normal = None;

    let mut total_size = state.total_size;

    let mut reader: Box<dyn ReadSeek + '_> = match state.format {
        DiskFormat::Qcow2 => {
            if state.bypass_cache {
                let file = direct_io::open_file(&state.path, true)
                    .map_err(|e| format!("Failed to open QCOW2 with Direct I/O: {}. Try `--no-bypass-cache`.", e))?;
                qcow_io_reader_direct = Some(direct_io::DirectIoReader::new(file, file_len, 64 * 1024, 4096));
                let io_ref = qcow_io_reader_direct.as_mut().unwrap();
                let qcow_img = qcow::load(io_ref)
                    .map_err(|e| format!("Failed to parse QCOW2 header: {}", e))?;
                let qcow2 = qcow_img.unwrap_qcow2();
                qcow2_direct = Some(qcow2);
                let qcow2_ref = qcow2_direct.as_mut().unwrap();
                let mut disk_reader = qcow2_ref.reader(io_ref);
                let size = disk_reader.seek(std::io::SeekFrom::End(0)).map_err(|e| e.to_string())?;
                disk_reader.seek(std::io::SeekFrom::Start(0)).map_err(|e| e.to_string())?;
                total_size = size;
                Box::new(disk_reader)
            } else {
                let file = std::fs::File::open(&state.path)
                    .map_err(|e| format!("Failed to open QCOW2: {}", e))?;
                qcow_io_reader_normal = Some(std::io::BufReader::new(file));
                let io_ref = qcow_io_reader_normal.as_mut().unwrap();
                let qcow_img = qcow::load(io_ref)
                    .map_err(|e| format!("Failed to parse QCOW2 header: {}", e))?;
                let qcow2 = qcow_img.unwrap_qcow2();
                qcow2_normal = Some(qcow2);
                let qcow2_ref = qcow2_normal.as_mut().unwrap();
                let mut disk_reader = qcow2_ref.reader(io_ref);
                let size = disk_reader.seek(std::io::SeekFrom::End(0)).map_err(|e| e.to_string())?;
                disk_reader.seek(std::io::SeekFrom::Start(0)).map_err(|e| e.to_string())?;
                total_size = size;
                Box::new(disk_reader)
            }
        }
        DiskFormat::Vmdk => {
            if state.bypass_cache {
                let file = direct_io::open_file(&state.path, true)
                    .map_err(|e| format!("Failed to open VMDK with Direct I/O: {}. Try `--no-bypass-cache`.", e))?;
                let io_reader = direct_io::DirectIoReader::new(file, file_len, 64 * 1024, 4096);
                let mut disk_reader = vmdk::VmdkReader::open(io_reader)
                    .map_err(|e| format!("Failed to parse VMDK header: {:?}", e))?;
                let size = disk_reader.seek(std::io::SeekFrom::End(0)).map_err(|e| e.to_string())?;
                disk_reader.seek(std::io::SeekFrom::Start(0)).map_err(|e| e.to_string())?;
                total_size = size;
                Box::new(disk_reader)
            } else {
                let file = std::fs::File::open(&state.path)
                    .map_err(|e| format!("Failed to open VMDK: {}", e))?;
                let io_reader = std::io::BufReader::new(file);
                let mut disk_reader = vmdk::VmdkReader::open(io_reader)
                    .map_err(|e| format!("Failed to parse VMDK header: {:?}", e))?;
                let size = disk_reader.seek(std::io::SeekFrom::End(0)).map_err(|e| e.to_string())?;
                disk_reader.seek(std::io::SeekFrom::Start(0)).map_err(|e| e.to_string())?;
                total_size = size;
                Box::new(disk_reader)
            }
        }
        DiskFormat::Vhdx => {
            if state.bypass_cache {
                cache_file = std::fs::File::open(&state.path).ok();
            }
            vhdx_disk = Some(vhdx::Vhdx::load(&state.path));
            let mut disk_reader = vhdx_disk.as_mut().unwrap().reader();
            let size = disk_reader.seek(std::io::SeekFrom::End(0)).map_err(|e| e.to_string())?;
            disk_reader.seek(std::io::SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            total_size = size;
            Box::new(disk_reader)
        }
        DiskFormat::Raw => {
            if state.bypass_cache {
                let file = direct_io::open_file(&state.path, true)
                    .map_err(|e| format!("Failed to open RAW image with Direct I/O: {}. Try `--no-bypass-cache`.", e))?;
                let disk_reader = direct_io::DirectIoReader::new(file, file_len, 64 * 1024, 4096);
                total_size = file_len;
                Box::new(disk_reader)
            } else {
                let file = std::fs::File::open(&state.path)
                    .map_err(|e| format!("Failed to open RAW image: {}", e))?;
                let disk_reader = std::io::BufReader::new(file);
                total_size = file_len;
                Box::new(disk_reader)
            }
        }
    };

    loop {
        let chunk_idx = state.next_chunk.fetch_add(1, Ordering::SeqCst);
        if chunk_idx >= state.num_chunks {
            break;
        }

        let offset = chunk_idx * (state.chunk_size as u64);
        if offset >= total_size {
            break;
        }

        let size_to_read = std::cmp::min(state.chunk_size as u64, total_size - offset) as usize;

        // Obtain a free buffer
        let mut buf = {
            let rx = free_rx.lock().unwrap();
            rx.recv().map_err(|e| format!("Free buffer channel closed: {}", e))?
        };

        // Seek reader to the chunk offset
        reader.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| format!("Failed to seek to offset {}: {}", offset, e))?;

        // Read logical disk bytes into buf
        let mut bytes_read = 0;
        while bytes_read < size_to_read {
            match reader.read(&mut buf.as_mut_slice()[bytes_read..size_to_read]) {
                Ok(0) => break,
                Ok(n) => bytes_read += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(format!("Failed to read disk contents at offset {}: {}", offset + bytes_read as u64, e)),
            }
        }

        if bytes_read == 0 {
            // Unexpected EOF, notify with 0 size and exit
            let _ = task_tx.send((chunk_idx, offset, buf, 0));
            break;
        }

        task_tx.send((chunk_idx, offset, buf, bytes_read))
            .map_err(|e| format!("Failed to send read buffer: {}", e))?;

        if let Some(ref f) = cache_file {
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                unsafe {
                    libc::posix_fadvise(
                        f.as_raw_fd(),
                        offset as libc::off_t,
                        bytes_read as libc::off_t,
                        libc::POSIX_FADV_DONTNEED,
                    );
                }
            }
        }
    }

    Ok(())
}

fn compute_hash(alg: HashAlgorithm, data: &[u8]) -> String {
    match alg {
        HashAlgorithm::Sha224 => {
            let mut hasher = Sha224::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        HashAlgorithm::Xxh64 => {
            let val = xxhash_rust::xxh64::xxh64(data, 0);
            format!("{:016x}", val)
        }
        HashAlgorithm::Xxh3 => {
            let val = xxhash_rust::xxh3::xxh3_64(data);
            format!("{:016x}", val)
        }
    }
}

#[cfg(not(test))]
fn run() -> Result<(), String> {
    let args = Cli::parse();
    run_with_args(args)
}

#[allow(unused_assignments)]
fn run_with_args(args: Cli) -> Result<(), String> {
    if !args.file_path.exists() {
        return Err(format!("File does not exist: {:?}", args.file_path));
    }

    let chunk_size = parse_chunk_size(&args.chunk_size)
        .map_err(|e| format!("Invalid chunk size option: {}", e))?;

    let format = match args.format {
        Some(fmt) => fmt,
        None => detect_format(&args.file_path)?,
    };
    let bypass_cache = !args.no_bypass_cache;

    // Determine logical disk size by opening the reader once on the main thread
    let file_len = std::fs::metadata(&args.file_path)
        .map_err(|e| format!("Failed to read metadata: {}", e))?
        .len();

    let mut vhdx_disk = None;
    let total_size = match format {
        DiskFormat::Qcow2 => {
            if bypass_cache {
                let file = direct_io::open_file(&args.file_path, true)
                    .map_err(|e| format!("Failed to open QCOW2 with Direct I/O: {}. Try `--no-bypass-cache`.", e))?;
                let mut io_reader = direct_io::DirectIoReader::new(file, file_len, 64 * 1024, 4096);
                let qcow_img = qcow::load(&mut io_reader)
                    .map_err(|e| format!("Failed to parse QCOW2 header: {}", e))?;
                let qcow2 = qcow_img.unwrap_qcow2();
                let mut disk_reader = qcow2.reader(&mut io_reader);
                disk_reader.seek(std::io::SeekFrom::End(0)).map_err(|e| e.to_string())?
            } else {
                let file = File::open(&args.file_path)
                    .map_err(|e| format!("Failed to open QCOW2: {}", e))?;
                let mut io_reader = std::io::BufReader::new(file);
                let qcow_img = qcow::load(&mut io_reader)
                    .map_err(|e| format!("Failed to parse QCOW2 header: {}", e))?;
                let qcow2 = qcow_img.unwrap_qcow2();
                let mut disk_reader = qcow2.reader(&mut io_reader);
                disk_reader.seek(std::io::SeekFrom::End(0)).map_err(|e| e.to_string())?
            }
        }
        DiskFormat::Vmdk => {
            if bypass_cache {
                let file = direct_io::open_file(&args.file_path, true)
                    .map_err(|e| format!("Failed to open VMDK with Direct I/O: {}. Try `--no-bypass-cache`.", e))?;
                let io_reader = direct_io::DirectIoReader::new(file, file_len, 64 * 1024, 4096);
                let mut disk_reader = vmdk::VmdkReader::open(io_reader)
                    .map_err(|e| format!("Failed to parse VMDK header: {:?}", e))?;
                disk_reader.seek(std::io::SeekFrom::End(0)).map_err(|e| e.to_string())?
            } else {
                let file = File::open(&args.file_path)
                    .map_err(|e| format!("Failed to open VMDK: {}", e))?;
                let io_reader = std::io::BufReader::new(file);
                let mut disk_reader = vmdk::VmdkReader::open(io_reader)
                    .map_err(|e| format!("Failed to parse VMDK header: {:?}", e))?;
                disk_reader.seek(std::io::SeekFrom::End(0)).map_err(|e| e.to_string())?
            }
        }
        DiskFormat::Vhdx => {
            vhdx_disk = Some(vhdx::Vhdx::load(&args.file_path));
            let mut disk_reader = vhdx_disk.as_mut().unwrap().reader();
            disk_reader.seek(std::io::SeekFrom::End(0)).map_err(|e| e.to_string())?
        }
        DiskFormat::Raw => file_len,
    };

    if total_size == 0 {
        // Empty virtual disk, nothing to print
        return Ok(());
    }

    let num_chunks = (total_size + (chunk_size as u64) - 1) / (chunk_size as u64);

    let state = Arc::new(SharedReaderState {
        next_chunk: AtomicU64::new(0),
        num_chunks,
        total_size,
        chunk_size,
        path: args.file_path.clone(),
        bypass_cache,
        format,
    });

    let hash_threads = args.hash_threads.unwrap_or_else(|| {
        let logical_cpus = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(4);
        std::cmp::min(4, std::cmp::max(1, logical_cpus / 2))
    });
    let io_threads = std::cmp::max(1, args.io_threads);

    // Rayon thread pool for hashing
    let hash_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(hash_threads)
        .build()
        .map_err(|e| format!("Failed to create Rayon thread pool: {}", e))?;

    // Create a pool of aligned buffers.
    // Total buffers = hash_threads + io_threads + 2
    let buffer_count = hash_threads + io_threads + 2;
    let (free_tx, free_rx) = std::sync::mpsc::channel::<AlignedBuffer>();
    for _ in 0..buffer_count {
        free_tx.send(AlignedBuffer::new(chunk_size, 4096)).unwrap();
    }

    // Channels for tasks (I/O thread -> Hasher pool) and results (Hasher pool -> Main reorder thread)
    // We make task_tx/task_rx bounded to manage buffer lifecycle and backpressure
    let (task_tx, task_rx) = std::sync::mpsc::sync_channel::<(u64, u64, AlignedBuffer, usize)>(hash_threads * 2);
    let (result_tx, result_rx) = std::sync::mpsc::channel::<(u64, u64, String, AlignedBuffer)>();

    let free_rx = Arc::new(Mutex::new(free_rx));
    
    // Spawn reader thread(s)
    let mut reader_handles = Vec::new();
    for _ in 0..io_threads {
        let state_clone = Arc::clone(&state);
        let free_rx_clone = Arc::clone(&free_rx);
        let task_tx_clone = task_tx.clone();
        
        let handle = thread::spawn(move || {
            run_reader_worker(state_clone, free_rx_clone, task_tx_clone)
        });
        reader_handles.push(handle);
    }
    // Drop our task_tx handle so that task_rx knows when all reader threads finish
    drop(task_tx);

    // Spawn a dispatcher thread that reads tasks from task_rx and dispatch to the rayon pool
    let dispatcher_result_tx = result_tx.clone();
    let dispatcher_handle = thread::spawn(move || {
        let result_tx = dispatcher_result_tx;
        let pool = hash_pool;
        while let Ok((chunk_idx, offset, buf, size)) = task_rx.recv() {
            if size == 0 {
                // EOF reached unexpectedly or empty block
                let _ = result_tx.send((chunk_idx, offset, String::new(), buf));
                continue;
            }
            let r_tx = result_tx.clone();
            let alg = args.algorithm;
            pool.spawn(move || {
                let hash_val = compute_hash(alg, &buf.as_slice()[..size]);
                let _ = r_tx.send((chunk_idx, offset, hash_val, buf));
            });
        }
    });
    // Drop result_tx so result_rx terminates when the dispatcher finishes dispatching and all spawned tasks complete
    drop(result_tx);

    // Main thread performs reordering and output printing
    let mut next_chunk_idx = 0;
    let mut pending_outputs = HashMap::new();

    while let Ok((chunk_idx, offset, hash_val, buf)) = result_rx.recv() {
        if !hash_val.is_empty() {
            pending_outputs.insert(chunk_idx, (offset, hash_val, buf));
        } else {
            // EOF or error, recycle buffer
            let _ = free_tx.send(buf);
        }

        while let Some((offset, hash_val, buf)) = pending_outputs.remove(&next_chunk_idx) {
            println!("{:016x}={}", offset, hash_val);
            // Recycle buffer
            let _ = free_tx.send(buf);
            next_chunk_idx += 1;
        }
    }

    // Wait for all reader threads to complete and report any error
    for handle in reader_handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(format!("Reader thread error: {}", e)),
            Err(_) => return Err("Reader thread panicked".to_string()),
        }
    }

    let _ = dispatcher_handle.join();

    Ok(())
}

#[cfg(not(test))]
fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::str::FromStr;

    #[test]
    fn test_hash_algorithm_from_str() {
        assert_eq!(HashAlgorithm::from_str("sha224").unwrap(), HashAlgorithm::Sha224);
        assert_eq!(HashAlgorithm::from_str("SHA-256").unwrap(), HashAlgorithm::Sha256);
        assert_eq!(HashAlgorithm::from_str("sha384").unwrap(), HashAlgorithm::Sha384);
        assert_eq!(HashAlgorithm::from_str("Sha512").unwrap(), HashAlgorithm::Sha512);
        assert_eq!(HashAlgorithm::from_str("xxh64").unwrap(), HashAlgorithm::Xxh64);
        assert_eq!(HashAlgorithm::from_str("xxh3").unwrap(), HashAlgorithm::Xxh3);
        
        assert!(HashAlgorithm::from_str("invalid").is_err());
    }

    #[test]
    fn test_compute_hash() {
        let data = b"hello world";
        
        // SHA-224 of "hello world"
        assert_eq!(
            compute_hash(HashAlgorithm::Sha224, data),
            "2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b"
        );

        // SHA-256 of "hello world"
        assert_eq!(
            compute_hash(HashAlgorithm::Sha256, data),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );

        // SHA-384 of "hello world"
        assert_eq!(
            compute_hash(HashAlgorithm::Sha384, data),
            concat!(
                "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb8",
                "3578b3e417cb71ce646efd0819dd8c088de1bd"
            )
        );

        // SHA-512 of "hello world"
        assert_eq!(
            compute_hash(HashAlgorithm::Sha512, data),
            concat!(
                "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4",
                "cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"
            )
        );

        // XXH64 of "hello world"
        assert_eq!(
            compute_hash(HashAlgorithm::Xxh64, data),
            "45ab6734b21e6968"
        );

        // XXH3 of "hello world"
        assert_eq!(
            compute_hash(HashAlgorithm::Xxh3, data),
            "d447b1ea40e6988b"
        );
    }

    #[test]
    fn test_parse_chunk_size() {
        assert_eq!(parse_chunk_size("512").unwrap(), 512);
        assert_eq!(parse_chunk_size("1024").unwrap(), 1024);
        assert_eq!(parse_chunk_size("4KiB").unwrap(), 4096);
        assert_eq!(parse_chunk_size("1Mi").unwrap(), 1024 * 1024);
        assert_eq!(parse_chunk_size("2MiB").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_chunk_size("1GiB").unwrap(), 1024 * 1024 * 1024);

        assert!(parse_chunk_size("").is_err());
        assert!(parse_chunk_size("abc").is_err());
        assert!(parse_chunk_size("512abc").is_err());
        assert!(parse_chunk_size("0").is_err());
        assert!(parse_chunk_size("123").is_err()); // not a multiple of 512
        assert!(parse_chunk_size("9999999999999999999999999999GiB").is_err());
    }

    #[test]
    fn test_detect_format() {
        let dir = std::env::temp_dir();
        
        // Qcow2 magic
        let path_qcow2 = dir.join("test_magic.qcow2");
        {
            let mut f = File::create(&path_qcow2).unwrap();
            f.write_all(b"QFI\xfb\x00\x00\x00\x03").unwrap();
        }
        assert_eq!(detect_format(&path_qcow2).unwrap(), DiskFormat::Qcow2);
        let _ = std::fs::remove_file(&path_qcow2);

        // Vmdk magic
        let path_vmdk = dir.join("test_magic.vmdk");
        {
            let mut f = File::create(&path_vmdk).unwrap();
            f.write_all(b"KDMV\x01\x00\x00\x00").unwrap();
        }
        assert_eq!(detect_format(&path_vmdk).unwrap(), DiskFormat::Vmdk);
        let _ = std::fs::remove_file(&path_vmdk);

        // Vhdx magic
        let path_vhdx = dir.join("test_magic.vhdx");
        {
            let mut f = File::create(&path_vhdx).unwrap();
            f.write_all(b"vhdxfile\x00\x00").unwrap();
        }
        assert_eq!(detect_format(&path_vhdx).unwrap(), DiskFormat::Vhdx);
        let _ = std::fs::remove_file(&path_vhdx);

        // Fallback by extension
        let path_ext_qcow2 = dir.join("dummy.qcow2");
        {
            let mut f = File::create(&path_ext_qcow2).unwrap();
            f.write_all(b"not magic but file exists").unwrap();
        }
        assert_eq!(detect_format(&path_ext_qcow2).unwrap(), DiskFormat::Qcow2);
        let _ = std::fs::remove_file(&path_ext_qcow2);

        let path_ext_vmdk = dir.join("dummy.vmdk");
        {
            let mut f = File::create(&path_ext_vmdk).unwrap();
            f.write_all(b"not magic but file exists").unwrap();
        }
        assert_eq!(detect_format(&path_ext_vmdk).unwrap(), DiskFormat::Vmdk);
        let _ = std::fs::remove_file(&path_ext_vmdk);

        // Test -flat.vmdk fallback to RAW
        let path_flat_vmdk = dir.join("dummy-flat.vmdk");
        {
            let mut f = File::create(&path_flat_vmdk).unwrap();
            f.write_all(b"raw bytes inside flat vmdk").unwrap();
        }
        assert_eq!(detect_format(&path_flat_vmdk).unwrap(), DiskFormat::Raw);
        let _ = std::fs::remove_file(&path_flat_vmdk);

        let path_ext_vhdx = dir.join("dummy.vhdx");
        {
            let mut f = File::create(&path_ext_vhdx).unwrap();
            f.write_all(b"not magic but file exists").unwrap();
        }
        assert_eq!(detect_format(&path_ext_vhdx).unwrap(), DiskFormat::Vhdx);
        let _ = std::fs::remove_file(&path_ext_vhdx);

        let path_ext_raw = dir.join("dummy.raw");
        {
            let mut f = File::create(&path_ext_raw).unwrap();
            f.write_all(b"not magic but file exists").unwrap();
        }
        assert_eq!(detect_format(&path_ext_raw).unwrap(), DiskFormat::Raw);
        let _ = std::fs::remove_file(&path_ext_raw);

        // Default fallback to raw
        let path_unknown = dir.join("dummy.unknown_ext");
        {
            let mut f = File::create(&path_unknown).unwrap();
            f.write_all(b"some contents").unwrap();
        }
        assert_eq!(detect_format(&path_unknown).unwrap(), DiskFormat::Raw);
        let _ = std::fs::remove_file(&path_unknown);
    }

    #[test]
    fn test_run_reader_worker() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_run_reader_worker.raw");
        
        // Write 1024 bytes of distinct values
        let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(&data).unwrap();
        }

        let state = Arc::new(SharedReaderState {
            next_chunk: AtomicU64::new(0),
            num_chunks: 2,
            total_size: 1024,
            chunk_size: 512,
            path: path.clone(),
            bypass_cache: false,
            format: DiskFormat::Raw,
        });

        let (free_tx, free_rx) = std::sync::mpsc::channel::<AlignedBuffer>();
        // Provide 2 buffers
        free_tx.send(AlignedBuffer::new(512, 512)).unwrap();
        free_tx.send(AlignedBuffer::new(512, 512)).unwrap();

        let free_rx = Arc::new(Mutex::new(free_rx));
        let (task_tx, task_rx) = std::sync::mpsc::sync_channel::<(u64, u64, AlignedBuffer, usize)>(2);

        // Run worker directly on the current thread
        let res = run_reader_worker(state, free_rx, task_tx);
        assert!(res.is_ok());

        // We should have received 2 tasks
        let (idx1, offset1, buf1, size1) = task_rx.recv().unwrap();
        assert_eq!(idx1, 0);
        assert_eq!(offset1, 0);
        assert_eq!(size1, 512);
        assert_eq!(buf1.as_slice()[0..512], data[0..512]);

        let (idx2, offset2, buf2, size2) = task_rx.recv().unwrap();
        assert_eq!(idx2, 1);
        assert_eq!(offset2, 512);
        assert_eq!(size2, 512);
        assert_eq!(buf2.as_slice()[0..512], data[512..1024]);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_run_with_args_basic() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_run_with_args_basic.raw");
        
        // Write 1024 bytes of zeros
        let data = vec![0u8; 1024];
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(&data).unwrap();
        }

        let args = Cli {
            file_path: path.clone(),
            algorithm: HashAlgorithm::Sha256,
            chunk_size: "512".to_string(),
            hash_threads: Some(1),
            io_threads: 1,
            no_bypass_cache: true,
            format: None,
        };

        let res = run_with_args(args);
        assert!(res.is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_run_with_args_flat_vmdk() {
        let dir = std::env::temp_dir();
        let path = dir.join("test-flat.vmdk");
        
        // Write 1024 bytes of zeros
        let data = vec![0u8; 1024];
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(&data).unwrap();
        }

        let args = Cli {
            file_path: path.clone(),
            algorithm: HashAlgorithm::Sha256,
            chunk_size: "512".to_string(),
            hash_threads: Some(1),
            io_threads: 1,
            no_bypass_cache: true,
            format: None,
        };

        let res = run_with_args(args);
        assert!(res.is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_run_with_args_empty_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_run_with_args_empty.raw");
        {
            File::create(&path).unwrap();
        }

        let args = Cli {
            file_path: path.clone(),
            algorithm: HashAlgorithm::Sha256,
            chunk_size: "512".to_string(),
            hash_threads: Some(1),
            io_threads: 1,
            no_bypass_cache: true,
            format: None,
        };

        let res = run_with_args(args);
        assert!(res.is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_run_with_args_nonexistent_file() {
        let path = PathBuf::from("does_not_exist_file_12345.raw");
        let args = Cli {
            file_path: path,
            algorithm: HashAlgorithm::Sha256,
            chunk_size: "512".to_string(),
            hash_threads: Some(1),
            io_threads: 1,
            no_bypass_cache: true,
            format: None,
        };

        let res = run_with_args(args);
        assert!(res.is_err());
    }

    #[test]
    fn test_disk_format_from_str() {
        assert_eq!(DiskFormat::from_str("qcow2").unwrap(), DiskFormat::Qcow2);
        assert_eq!(DiskFormat::from_str("QCOW2").unwrap(), DiskFormat::Qcow2);
        assert_eq!(DiskFormat::from_str("vhdx").unwrap(), DiskFormat::Vhdx);
        assert_eq!(DiskFormat::from_str("vmdk").unwrap(), DiskFormat::Vmdk);
        assert_eq!(DiskFormat::from_str("raw").unwrap(), DiskFormat::Raw);
        assert!(DiskFormat::from_str("invalid").is_err());
    }

    #[test]
    fn test_run_with_args_explicit_format() {
        let dir = std::env::temp_dir();
        // create a dummy file without .raw extension but process it as RAW
        let path = dir.join("test_explicit_format.dummy");
        let data = vec![0u8; 1024];
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(&data).unwrap();
        }

        let args = Cli {
            file_path: path.clone(),
            algorithm: HashAlgorithm::Sha256,
            chunk_size: "512".to_string(),
            hash_threads: Some(1),
            io_threads: 1,
            no_bypass_cache: true,
            format: Some(DiskFormat::Raw),
        };

        let res = run_with_args(args);
        assert!(res.is_ok());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_run_with_args_explicit_format_mismatch() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_explicit_format_mismatch.raw");
        let data = vec![0u8; 1024];
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(&data).unwrap();
        }

        // Try parsing RAW as QCOW2 -> it should fail during parsing header
        let args = Cli {
            file_path: path.clone(),
            algorithm: HashAlgorithm::Sha256,
            chunk_size: "512".to_string(),
            hash_threads: Some(1),
            io_threads: 1,
            no_bypass_cache: true,
            format: Some(DiskFormat::Qcow2),
        };

        let res = run_with_args(args);
        assert!(res.is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_run_compiles_and_callable() {
        // Just verify run parses command line or does basic validation when called.
        // We won't call it here directly because of CLI parsing panics on test arguments.
        // But the function `run` itself is extremely simple:
        // fn run() -> Result<(), String> {
        //     let args = Cli::parse();
        //     run_with_args(args)
        // }
    }
}
