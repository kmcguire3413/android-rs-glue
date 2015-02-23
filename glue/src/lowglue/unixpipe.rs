use std::sync::Arc;
use std::marker::PhantomData;
use std::mem::transmute;
use libc;

/// Provides a safe implementation of a pipe.
pub struct UnixPipe {
    rd:     libc::c_int,
    wr:     libc::c_int,
}

impl Drop for UnixPipe {
    fn drop(&mut self) {
        use libc::funcs::posix88::unistd::close;
        unsafe { 
            close(self.rd);
            close(self.wr);
        }
    }
}

impl UnixPipe {
    pub fn new() -> UnixPipe {
        use libc::funcs::posix88::unistd::pipe;
        let halves: [libc::c_int; 2] = [0, 0];
        unsafe { pipe(transmute(&halves)); }
        UnixPipe {
            rd:     halves[0],
            wr:     halves[1],
        }
    }

    pub fn getrdfd(&self) -> libc::c_int {
        self.rd
    }

    pub fn getwrfd(&self) -> libc::c_int {
        self.wr
    }

    pub fn write(&self, buf: &[u8], sz: usize) -> usize {
        use libc::funcs::posix88::unistd::write;
        unsafe { 
            if sz > buf.len() {
                panic!("write past end of buffer");
            }
            write(self.wr, transmute(buf.as_ptr()), sz as libc::size_t) as usize 
        }
    }

    pub fn read(&self, buf: &mut [u8], sz: usize) -> usize {
        use libc::funcs::posix88::unistd::read;
        unsafe {
            if sz > buf.len() {
                panic!("read past end of buffer");
            }
            read(self.rd, transmute(buf.as_ptr()), sz as libc::size_t) as usize
        }
    }

    pub fn readtype<T: Copy>(&self) -> T {
        unsafe { self.readtypeunsafe::<T>() }
    }

    pub unsafe fn readtypeunsafe<T>(&self) -> T {
        use libc::funcs::posix88::unistd::read;
        use std::mem::zeroed;
        use std::mem::size_of;
        let val: T = zeroed();
        if read(self.rd, transmute(&val), size_of::<T>() as u32) as usize != size_of::<T>() {
            panic!("read short of expected size");
        }
        val
    }

    pub fn writetype<T>(&self, val: T) {
        use libc::funcs::posix88::unistd::write;
        use std::mem::size_of;
        if unsafe { write(self.wr, transmute(&val), size_of::<T>() as u32) as usize != size_of::<T>() } {
            panic!("write short of expected size");
        }
    }
}

pub struct StaticTypeUnixPipe<T> {
    ty:         PhantomData<T>,
    pub pipe:   Arc<UnixPipe>,
}

impl<T> Clone for StaticTypeUnixPipe<T> {
    fn clone(&self) -> StaticTypeUnixPipe<T> {
        StaticTypeUnixPipe {
            ty:     PhantomData,
            pipe:   self.pipe.clone(),
        }
    }
}

impl<T: Copy> StaticTypeUnixPipe<T> {
    pub fn wrap(pipe: UnixPipe) -> StaticTypeUnixPipe<T> {
        StaticTypeUnixPipe {
            ty:     PhantomData,
            pipe:   Arc::new(pipe),
        }
    }

    pub fn read(&self) -> T {
        self.pipe.readtype::<T>()
    }

    pub fn write(&self, t: T) {
        self.pipe.writetype(t);
    }
}