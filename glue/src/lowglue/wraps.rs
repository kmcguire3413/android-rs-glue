use std::any::Any;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};
use std::mem::{transmute, transmute_copy};
use std::collections::HashMap;
use std::marker::Reflect;
use super::ffi;

use libc;

/// Wraps the NDK object and provides a easier calling interface for functions.
pub struct InputEvent { raw: *mut ffi::AInputEvent }
/// Wraps the NDK object and provides a easier calling interface for functions.
pub struct Configuration { raw: *mut ffi::AConfiguration }
unsafe impl Send for Configuration { }
/// Wraps the NDK object and provides a easier calling interface for functions.
pub struct InputQueue { raw: *mut ffi::AInputQueue }
unsafe impl Send for InputQueue { }
/// Wsraps the NDK object and provides a easier calling interface for functions.
pub struct Window;
/// Wraps the NDK object and provides a easier calling interface for functions.
pub struct Rect;
/// Wraps the NDK object and provides a easier calling interface for functions.
pub struct NativeActivity { raw: *mut ffi::ANativeActivity }
/// Wraps the NDK object and provides a easier calling interface for functions.
pub struct NativeWindow { raw: *mut ffi::ANativeWindow }
unsafe impl Send for NativeWindow { }

impl Configuration {
    pub unsafe fn wrap(raw: *mut ffi::AConfiguration) -> Configuration { Configuration { raw: raw } }
    pub fn getptr(&self) -> *mut ffi::AConfiguration { self.raw }
}

impl InputEvent {
    pub unsafe fn wrap(raw: *mut ffi::AInputEvent) -> InputEvent { InputEvent { raw: raw } }
    pub fn getptr(&self) -> *mut ffi::AInputEvent { self.raw }
}

/// Wraps the NDK object and provides a easier calling interface for functions.
struct LooperInner {
    raw:    *mut ffi::ALooper,
    /// Any should be `Arc<LooperCallbackData<T>>`.
    cbfd:   Mutex<HashMap<libc::c_int, (usize, usize)>>,
}

pub struct Looper {
    inner:      Arc<LooperInner>,
}
unsafe impl Send for Looper { }

/// The glue between the NDK and Rust, for the Looper callback.
///
/// We have to do a little work here. The `data` is essentially an
/// `Arc<LooperCallbackData>`, but it is a shadow. By shadow I mean
/// that it exists somewhere else. Since this is a shadow we must be
/// careful not to drop it from memory. So we take a reference to it
/// and then we clone that and provide it to the Rust callback.
extern "C" fn looper_callback_entry<T>(_u1: libc::c_int, _u2: libc::c_int, data: *mut libc::c_void) -> libc::c_int {
    println!("[LooperCallbackEntry] called data:{:p}", data);
    let lcb: &Arc<LooperCallbackData<T>> = unsafe { transmute(&data) };
    // Since the function pointer is Copy it stays in place.
    lcb.rcb.unwrap()(lcb.clone())
}

fn looper_tls_init() -> RefCell<Option<Looper>> {
    RefCell::new(Option::None)
}

thread_local!(static LOOPER_TLS: RefCell<Option<Looper>> = looper_tls_init());

/// The data representing a Rust callback for the Looper.
pub struct LooperCallbackData<T> {
    /// Function pointer to the Rust callback.
    rcb:        Option<fn(Arc<LooperCallbackData<T>>) -> i32>,
    /// Looper issuing this callback.
    pub looper: Looper,
    /// File descriptor
    pub fd:     libc::c_int,
    /// Identification value
    pub ident:  libc::c_int,
    /// Events that the looper executed the callback for.
    pub events: libc::c_int,
    /// The data passed in when registering the callback.
    pub data:   T,
}

impl<T> Reflect for LooperCallbackData<T> { }

/// Represents a `LooperPollResult::Ready` state.
pub struct LooperPollEvent {
    /// Identification value.
    pub ident:          libc::c_int,
    /// File descriptor.
    pub fd:             libc::c_int,
    /// Signaled events.
    pub events:         libc::c_int,
    /// An Arc<LooperCallbackData<T>>. We just do not know what type.
    pub data:           Option<Box<Any + Send>>,
    /// The smart pointer representing Arc<looperCallbackData<T>>.
    pub dataptr:        *mut libc::c_void,
}

/// Returned from a `pollAll` or `pollOnce` call.
pub enum LooperPollResult {
    /// Awoken using `Looper::wake` or the native FFI call.
    Wake,
    /// One or more callbacks were executed.
    Callback,
    /// Timeout expired.
    Timeout,
    /// Error occured.
    Error,
    /// Partially processed return.
    HasIdent(libc::c_int),
    /// Signals that a descriptor is ready to be processed.
    Ready(LooperPollEvent),
}

impl LooperPollResult {
    pub fn from_int(val: libc::c_int) -> LooperPollResult {
        match val {
            ffi::ALOOPER_POLL_WAKE => LooperPollResult::Wake,
            ffi::ALOOPER_POLL_CALLBACK => LooperPollResult::Callback,
            ffi::ALOOPER_POLL_TIMEOUT => LooperPollResult::Timeout,
            ffi::ALOOPER_POLL_ERROR => LooperPollResult::Error,
            _ => LooperPollResult::HasIdent(val),
        }
    }
}

impl Clone for Looper {
    fn clone(&self) -> Looper {
        Looper {
            inner: self.inner.clone(),
        }
    }
}

impl Looper {
    /// Wrap a NDK FFI raw pointer to provide this safe interface.
    pub unsafe fn wrap(raw: *mut ffi::ALooper) -> Looper { 
        Looper {
            inner:      Arc::new(LooperInner {
                raw:        raw,
                cbfd:       Mutex::new(HashMap::new()),
            }),
        } 
    }

    /// Get raw pointer to use with the NDK FFI.
    pub fn getptr(&self) -> *mut ffi::ALooper {
        self.inner.raw
    }

    /// Wake the looper.
    pub fn wake(&self) {
        unsafe { ffi::ALooper_wake(self.inner.raw); }
    }

    /// Only poll once.
    pub fn pollonce(&self, timeout: libc::c_int) -> LooperPollResult {
        self.poll(timeout, true)
    }

    /// Keep polling until we must return.
    pub fn pollall(&self, timeout: libc::c_int) -> LooperPollResult {
        self.poll(timeout, false)
    }

    /// You can select between `pollOnce` and `pollAll` behaviors.
    pub fn poll(&self, timeout: libc::c_int, once: bool) -> LooperPollResult {
        let outfd: libc::c_int = 0;
        let outevents: libc::c_int = 0;
        let outdata: *mut libc::c_void = 0 as *mut libc::c_void;
        let ret;
        if once {
            ret = LooperPollResult::from_int(unsafe { ffi::ALooper_pollOnce(timeout, transmute(&outfd), transmute(&outevents), transmute(&outdata)) })
        } else {
            ret = LooperPollResult::from_int(unsafe { ffi::ALooper_pollAll(timeout, transmute(&outfd), transmute(&outevents), transmute(&outdata)) });
        }
        match ret {
            LooperPollResult::HasIdent(val) =>  
                    // Translate from ::HasIdent to ::Ready.
                    LooperPollResult::Ready(match self.inner.cbfd.lock().unwrap().get(&outfd) {
                        Some(mcb) => LooperPollEvent {
                            ident:      val,
                            fd:         outfd,
                            events:     outevents,
                            dataptr:    outdata,
                            data:       Option::Some(unsafe { transmute::<(usize, usize), Box<Any + Send>>(*mcb) }),
                        },
                        None => LooperPollEvent { 
                            ident:      val,
                            fd:         outfd,
                            events:     outevents,
                            dataptr:    outdata,
                            data:       Option::None,
                        },
                    }),
            // Just return it 'as is'.
            val => val,
        }
    }

    pub fn acquire(&self) {
        unsafe { ffi::ALooper_acquire(self.inner.raw); }
    }

    /// Remove the file descriptor from the looper.
    pub fn removefd(&self, fd: libc::c_int) -> Result<Box<Any>, libc::c_int> {
        let ret = unsafe { ffi::ALooper_removeFd(self.getptr(), fd) };
        if ret != 0 {
            Result::Err(ret)
        } else {
            // (*) This allows the caller to salvage anything it needs to.
            // (*) There may exist more instances of this Arc<LooperCallbackData<T>>
            // (*) The shadow only existed in the Looper system internals, and it
            //     should never the see light of day again (dead).
            Result::Ok(unsafe { transmute::<(usize, usize), Box<Any + Send>>(self.inner.cbfd.lock().unwrap().remove(&fd).unwrap()) } )
        }
    }

    /// Add a file descriptor to the looper for monitoring for events.
    ///
    ///      // Get reference to the activity state (application state).
    ///      let app = get_app();
    ///      // Get reference to the safe looper object.
    ///      let looper = app.looper.lock().unwrap().as_ref().unwrap().clone();
    ///      // Create a pipe to test with.
    ///      let mypipe = StaticTypeUnixPipe::<u8>::wrap(UnixPipe::new());
    ///      // Create our callback.
    ///      fn mycallback(data: Arc<LooperCallbackData<u64>>) -> libc::c_int {
    ///          println!("callback called");
    ///          1
    ///      }
    ///      // Add callback, file descriptor, and data to the looper.
    ///      looper.addFd(
    ///              mypipe.pipe.getrdfd(), ffi::LOOPER_ID_USER, ffi::ALOOPER_EVENT_INPUT, 
    ///              Option::Some(mycallback),
    ///              84u64
    ///      );
    ///      // Wait until the activity is destroyed.
    ///      loop {
    ///          let event = eventsrx.recv().unwrap();
    ///          println!("event: {:?}", event);
    ///          match event {
    ///              Event::Destroy => {
    ///                   break;
    ///              },
    ///              _ => (),
    ///          }
    ///      }
    pub fn addfd<T: Send + 'static>(&self, fd: libc::c_int, ident: libc::c_int, events: libc::c_int, cb: Option<fn(Arc<LooperCallbackData<T>>) -> libc::c_int>, data: T) -> Result<(), libc::c_int> {
        let wcb: ffi::ALooper_callbackFunc = looper_callback_entry::<T>;

        // The API states that if a callback is provided then ident shall be 
        // `ALOOPER_POLL_CALLBACK`, and from experience if you do not do this
        // then the callback may be executed, and if so the poll call may act
        // like no callback was executed, which could be very bad.
        let xident = if cb.is_some() {
            ffi::ALOOPER_POLL_CALLBACK
        } else {
            ident
        };

        let lcb = Arc::new(LooperCallbackData::<T> {
            data:       data,
            rcb:        cb,
            looper:     self.clone(),
            fd:         fd,
            ident:      ident,
            events:     events,
        });

        // Create a shadow of the `Arc<LooperCallbackData<T>>` as `dataptr`.
        let dataptr: *mut libc::c_void = unsafe { transmute_copy(&lcb) };
        let callret = unsafe { ffi::ALooper_addFd(self.inner.raw, fd, xident, events, wcb, dataptr) };
        if callret != 1 {
            return Result::Err(callret);
        }

        // Store it, else it drops, and the shadow becomes a dangling pointer.
        let mut cbfd = self.inner.cbfd.lock().unwrap();
        let tmp: Box<Any> = Box::new(lcb);
        cbfd.insert(fd, unsafe { transmute::<Box<Any>, (usize, usize)>(tmp) });
        Result::Ok(())
    }

    /// Get the current looper for this thread.
    pub fn forthread() -> Option<Looper> {
        let mut pullout: Option<Looper> = Option::None;

        // Get the looper from our thread local storage.
        LOOPER_TLS.with( | tls | {
            if tls.borrow().is_some() {
                pullout = Option::Some(tls.borrow().as_ref().unwrap().clone());
            }
        });

        if pullout.is_none() {
            // Try to get looper from FFI.
            let rawptr = unsafe { ffi::ALooper_forThread() };
            if !rawptr.is_null() {
                // Also set TLS with looper and wrap it.
                let looper = unsafe { Looper::wrap(rawptr) };
                let clonedlooper = looper.clone();
                LOOPER_TLS.with( | tls | {
                    *tls.borrow_mut() = Option::Some(clonedlooper);
                });
                pullout = Option::Some(looper);
            }
        }

        pullout
    }

    pub fn prepare(&self, opts: libc::c_int) -> Looper {
        let rawptr = unsafe { ffi::ALooper_prepare(opts) };
        let looper = unsafe { Looper::wrap(rawptr) };
        let clonedlooper = looper.clone();

        LOOPER_TLS.with( | tls | {
            *tls.borrow_mut() = Option::Some(clonedlooper);
        });

        return looper;
    }

    pub fn release(&self) {
        unsafe { ffi::ALooper_release(self.inner.raw); }
    }
}

impl NativeWindow {
    pub unsafe fn wrap(raw: *mut ffi::ANativeWindow) -> NativeWindow { NativeWindow { raw: raw } }
    pub fn getptr(&self) -> *mut ffi::ANativeWindow { self.raw }
}

/*
extern { pub fn AInputQueue_attachLooper(queue: *mut AInputQueue, looper: *mut ALooper, ident: libc::c_int, callback: ALooper_callbackFunc, data: *mut libc::c_void); }
extern { pub fn AInputQueue_detachLooper(queue: *mut AInputQueue); }
extern { pub fn AInputQueue_finishEvent(queue: *mut AInputQueue, event: *mut AInputEvent, handled: libc::c_int); }
extern { pub fn AInputQueue_getEvent(queue: *mut AInputQueue, outEvent: *mut *mut AInputEvent) -> libc::int32_t; }
extern { pub fn AInputQueue_hasEvents(queue: *mut AInputQueue) -> libc::int32_t; }
extern { pub fn AInputQueue_preDispatchEvent(queue: *mut AInputQueue, event: *mut AInputEvent) -> libc::int32_t; }
*/

impl InputQueue {
    pub unsafe fn wrap(raw: *mut ffi::AInputQueue) -> InputQueue { InputQueue { raw: raw } }
    pub fn getptr(&self) -> *mut ffi::AInputQueue { self.raw } 
}

impl NativeActivity {
    /// Low-cost wrapping operation.
    pub unsafe fn wrap(raw: *mut ffi::ANativeActivity) -> NativeActivity { NativeActivity { raw: raw } }
    /// Get raw pointer for object, to use with NDK API.
    pub fn getptr(&self) -> *mut ffi::ANativeActivity { self.raw }
}
