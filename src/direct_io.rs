#![allow(dead_code)]
use std::alloc::{alloc, dealloc, Layout};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::slice;

/// A memory-aligned buffer required for Direct I/O (O_DIRECT / FILE_FLAG_NO_BUFFERING)
pub struct AlignedBuffer {
    ptr: *mut u8,
    layout: Layout,
}

unsafe impl Send for AlignedBuffer {}
unsafe impl Sync for AlignedBuffer {}


impl AlignedBuffer {
    pub fn new(size: usize, align: usize) -> Self {
        let layout = Layout::from_size_align(size, align).expect("Invalid layout size/alignment");
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            panic!("Aligned allocation of {} bytes with alignment {} failed", size, align);
        }
        Self { ptr, layout }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.ptr, self.layout.size()) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
    }

    pub fn len(&self) -> usize {
        self.layout.size()
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr, self.layout);
        }
    }
}

/// A wrapper reader that ensures all I/O operations to the underlying file are
/// block-aligned and size-aligned, allowing seamless use of OS cache bypassing (Direct I/O).
pub struct DirectIoReader {
    file: File,
    buffer: AlignedBuffer,
    buf_offset: u64, // File offset corresponding to the start of the buffer
    buf_len: usize,   // Number of valid bytes currently in the buffer
    pos: u64,         // Current logical read cursor position
    file_len: u64,    // Total size of the file (to handle EOF and size limits)
    alignment: u64,
}

impl DirectIoReader {
    pub fn new(file: File, file_len: u64, buf_size: usize, alignment: usize) -> Self {
        Self {
            file,
            buffer: AlignedBuffer::new(buf_size, alignment),
            buf_offset: 0,
            buf_len: 0,
            pos: 0,
            file_len,
            alignment: alignment as u64,
        }
    }

    /// Retrieve the current position
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Retrieve the file length
    pub fn len(&self) -> u64 {
        self.file_len
    }
}

impl Read for DirectIoReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.file_len {
            return Ok(0); // EOF
        }

        let mut bytes_copied = 0;

        while bytes_copied < buf.len() && self.pos < self.file_len {
            // Check if our current logical position falls inside the buffered data range
            if self.pos >= self.buf_offset && self.pos < self.buf_offset + (self.buf_len as u64) {
                let offset_in_buf = (self.pos - self.buf_offset) as usize;
                let available_in_buf = self.buf_len - offset_in_buf;
                let to_copy = std::cmp::min(available_in_buf, buf.len() - bytes_copied);
                
                // Respect the logical file length limit
                let remaining_file = (self.file_len - self.pos) as usize;
                let to_copy = std::cmp::min(to_copy, remaining_file);

                if to_copy == 0 {
                    break;
                }

                buf[bytes_copied..bytes_copied + to_copy].copy_from_slice(
                    &self.buffer.as_slice()[offset_in_buf..offset_in_buf + to_copy]
                );

                self.pos += to_copy as u64;
                bytes_copied += to_copy;
            } else {
                // If pos is outside the buffer, we must load the aligned block containing pos
                let aligned_offset = self.pos - (self.pos % self.alignment);
                
                // Seek underlying file to the aligned offset
                self.file.seek(SeekFrom::Start(aligned_offset))?;

                // Read full aligned blocks from disk into the aligned buffer
                let temp_buf = self.buffer.as_mut_slice();
                let mut total_read = 0;

                while total_read < temp_buf.len() {
                    match self.file.read(&mut temp_buf[total_read..]) {
                        Ok(0) => break,
                        Ok(n) => total_read += n,
                        Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }

                if total_read == 0 {
                    break; // EOF
                }

                self.buf_offset = aligned_offset;
                // Truncate buf_len to match logical file bounds so we never serve padding bytes
                self.buf_len = std::cmp::min(
                    total_read,
                    (self.file_len.saturating_sub(aligned_offset)) as usize,
                );
            }
        }

        Ok(bytes_copied)
    }
}

impl Seek for DirectIoReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i64,
            SeekFrom::End(offset) => (self.file_len as i64) + offset,
            SeekFrom::Current(offset) => (self.pos as i64) + offset,
        };

        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot seek before start of file",
            ));
        }

        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

/// Open a file option with OS read cache bypassed if bypass_cache is true
pub fn open_file<P: AsRef<Path>>(path: P, bypass_cache: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    if bypass_cache {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_DIRECT);
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_NO_BUFFERING;
            options.custom_flags(FILE_FLAG_NO_BUFFERING);
        }
    }

    let file = options.open(path)?;

    if bypass_cache {
        #[cfg(target_os = "macos")]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                libc::fcntl(file.as_raw_fd(), libc::F_NOCACHE, 1);
            }
        }
    }

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_aligned_buffer_basic() {
        let size = 4096;
        let align = 4096;
        let mut buf = AlignedBuffer::new(size, align);
        assert_eq!(buf.len(), size);
        
        // Check pointer alignment
        let addr = buf.ptr as usize;
        assert_eq!(addr % align, 0);

        // Test writing/reading
        let slice = buf.as_mut_slice();
        for i in 0..size {
            slice[i] = (i % 256) as u8;
        }

        let read_slice = buf.as_slice();
        for i in 0..size {
            assert_eq!(read_slice[i], (i % 256) as u8);
        }
    }

    #[test]
    fn test_direct_io_reader_basic() {
        // Create a temporary file with known pattern
        let dir = std::env::temp_dir();
        let path = dir.join("test_direct_io_reader_basic.dat");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();

        let data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
        file.write_all(&data).unwrap();
        drop(file);

        // Open reader
        let file = File::open(&path).unwrap();
        let mut reader = DirectIoReader::new(file, 8192, 1024, 512);

        assert_eq!(reader.len(), 8192);
        assert_eq!(reader.position(), 0);

        // Read 10 bytes (unaligned offset 0, size 10)
        let mut buf = vec![0u8; 10];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(buf, &data[0..10]);
        assert_eq!(reader.position(), 10);

        // Seek forward
        let pos = reader.seek(SeekFrom::Start(100)).unwrap();
        assert_eq!(pos, 100);
        assert_eq!(reader.position(), 100);

        // Read crossing page boundaries
        let mut buf2 = vec![0u8; 2000];
        let n = reader.read(&mut buf2).unwrap();
        assert_eq!(n, 2000);
        assert_eq!(buf2, &data[100..2100]);
        assert_eq!(reader.position(), 2100);

        // Seek relative
        let pos = reader.seek(SeekFrom::Current(-100)).unwrap();
        assert_eq!(pos, 2000);
        assert_eq!(reader.position(), 2000);

        // Seek from end
        let pos = reader.seek(SeekFrom::End(-100)).unwrap();
        assert_eq!(pos, 8092);
        assert_eq!(reader.position(), 8092);

        // Read to EOF
        let mut buf3 = vec![0u8; 200];
        let n = reader.read(&mut buf3).unwrap();
        assert_eq!(n, 100);
        assert_eq!(buf3[0..100], data[8092..8192]);
        assert_eq!(reader.position(), 8192);

        // Read past EOF
        let n = reader.read(&mut buf3).unwrap();
        assert_eq!(n, 0);

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_direct_io_reader_seek_errors() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_direct_io_reader_seek.dat");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.write_all(b"hello world").unwrap();
        drop(file);

        let file = File::open(&path).unwrap();
        let mut reader = DirectIoReader::new(file, 11, 512, 512);

        // Seeking before 0 should error
        let res = reader.seek(SeekFrom::Start(0));
        assert!(res.is_ok());
        let res = reader.seek(SeekFrom::Current(-5));
        assert!(res.is_err());

        let res = reader.seek(SeekFrom::End(-20));
        assert!(res.is_err());

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_open_file_no_bypass() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_open_file_no_bypass.dat");
        {
            let mut file = File::create(&path).unwrap();
            file.write_all(b"test").unwrap();
        }

        // Test with bypass_cache = false
        let file = open_file(&path, false);
        assert!(file.is_ok());

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_open_file_with_bypass() {
        let dir = std::env::temp_dir();
        let path = dir.join("test_open_file_with_bypass.dat");
        {
            let mut file = File::create(&path).unwrap();
            file.write_all(b"test").unwrap();
        }

        // Try to open with bypass_cache = true
        let file = open_file(&path, true);
        // Note: O_DIRECT might not be supported on all build/CI environments (e.g. some tmpfs mounts).
        // So we accept both Ok or Error, but we verify it doesn't panic.
        if let Ok(mut f) = file {
            let mut buf = [0u8; 4];
            let _ = f.read(&mut buf);
        }

        let _ = std::fs::remove_file(&path);
    }
}
