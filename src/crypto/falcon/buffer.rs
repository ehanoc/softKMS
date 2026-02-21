use libc::c_void;
use std::alloc::{alloc, dealloc, Layout};

pub struct FalconBuffer {
    ptr: *mut u8,
    layout: Layout,
    size: usize,
}

impl FalconBuffer {
    pub fn new(size: usize) -> Self {
        let layout = Layout::array::<u8>(size).expect("invalid layout");
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            panic!("allocation failed");
        }
        Self { ptr, layout, size }
    }

    pub fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.ptr as *mut libc::c_void
    }

    pub fn as_ptr(&self) -> *const libc::c_void {
        self.ptr as *const libc::c_void
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.size) }
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for FalconBuffer {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr, self.layout) }
    }
}

pub struct ZeroizingBuffer {
    buffer: FalconBuffer,
}

impl ZeroizingBuffer {
    pub fn new(size: usize) -> Self {
        Self {
            buffer: FalconBuffer::new(size),
        }
    }

    pub fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.buffer.as_mut_ptr()
    }

    pub fn as_ptr(&self) -> *const libc::c_void {
        self.buffer.as_ptr()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    pub fn size(&self) -> usize {
        self.buffer.size()
    }
}

impl Drop for ZeroizingBuffer {
    fn drop(&mut self) {
        // Zero out memory before dropping
        unsafe {
            std::ptr::write_bytes(self.buffer.as_mut_ptr(), 0, self.buffer.size());
        }
    }
}
