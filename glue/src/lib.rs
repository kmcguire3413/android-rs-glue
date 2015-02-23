//!
//! You can make _any_ program run on Android with minimal non-intrusive 
//! modification using this library.
//!
//! See, https://github.com/tomaka/android-rs-glue, for detailed instructions!
//!
//! The libray allow you to run any program on Android, but it also allows you
//! to work specifically with the Android system if you desire. The following
//! sample application demonstrates both non-os specific code, and android 
//! specific code. 
//!
//! A example application:
//!
//!     // This code will only be included if android is the target.
//!     #[cfg(target_os = "android")]
//!     #[macro_use]
//!     extern crate android_glue;
//!     // This code will only be included if android is the target.
//!     #[cfg(target_os = "android")]
//!     android_start!(main);
//!     
//!     #[cfg(target_os = "android")]
//!     fn os_specific() {
//!         use std::sync::mpsc::channel;
//!         use android_glue::{Event, add_sender};    
//!         // Create a channel.
//!         let (eventstx, eventsrx) = channel::<Event>();
//!         // The following is optional, and will only work if you target Android.
//!         // Add the sender half of the channel so we can be sent events.
//!         add_sender(eventstx);
//!         loop {
//!             // Print the event since it implements the Debug trait.
//!             println!("{:?}", eventsrx.recv());
//!         }
//!     }
//!
//!     #[cfg(not(target_os = "android"))]
//!     fn os_specific() {
//!         println!("non-android");
//!     }
//!
//!
//!     fn main() {
//!         // Try `adb logcat *:D | grep RustAndroidGlue` when you run this 
//!         // program on android. If on any other platform it will work as
//!         // normal.    
//!         println!("HELLO WORLD");
//!         os_specific();
//!     }
#![feature(unsafe_destructor)]
#![feature(box_syntax, plugin, libc, core, collections, std_misc, set_stdio, convert)]

extern crate libc;
extern crate schedule_recv;

use std::any::Any;
use std::ffi::{CString};
use std::sync::mpsc::{Sender, channel};
use std::sync::{Mutex, Arc};
use std::mem::transmute;
use std::cell::RefCell;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::io::Write;
use std::marker::Reflect;

pub use lowglue::ActivityState;
pub use lowglue::InputEvent;
pub use lowglue::AndroidPollSource;

#[doc(hidden)]
pub mod ffi;
pub mod lowglue;

/// Initialize the TLS storage.
fn android_app_tls_init() -> RefCell<Option<Arc<ActivityState>>> {
    RefCell::new(Option::None)
}

/// The thread local storage to allow multiple activites to be started
/// from the same activity executable image.
thread_local!(static ANDROID_APP: RefCell<Option<Arc<ActivityState>>> = android_app_tls_init());

const MISSEDMAX: usize = 1024;

/// This is the structure that serves as user data in the android_app.
///
/// You can extend this structure through the usage of the `userdata` field
/// or by using the helper methods `setuserdata` and `getuserdata`. The data
/// that you set must be `Send` since it can potentially be accessed by more
/// than one thread.
#[doc(hidden)]
pub struct Context {
    senders:        Mutex<Vec<Sender<Event>>>,
    /// Any missed events are stored here.
    missed:         Mutex<Vec<Event>>,
    /// Better performance to track number of missed items.
    missedcnt:      AtomicUsize,
    /// Told to destroy?
    mustdestroy:    AtomicBool,
    /// User data extension. _(You are free to use this for your own purposes)_
    pub userdata:   Mutex<Box<Any + Send>>,
}

impl Context {
    /// Helper function to set the user data for this structure.
    ///
    /// You can use user data to extend this structure with your own fields. You
    /// can store anything you like. Then later retrieve a reference to it using
    /// `getuserdata`.
    pub fn setuserdata<T: 'static + Send + Sync + Reflect>(&self, value: T) {
        *self.userdata.lock().unwrap() = Box::new(Arc::new(value));
    }

    /// Helper function to get what was set as the user data for this structure.
    ///
    /// _If you need to detach the lifetime requirement consider setting a type
    /// that can be cloned or copied (if desired).
    pub fn getuserdata<T: 'static + Send + Sync + Reflect>(&self) -> Option<Arc<T>> {
        self.userdata.lock().unwrap().downcast_ref::<Arc<T>>().cloned()
    }
}

/// An event triggered by the Android environment.
#[derive(Debug,Clone,Copy)]
pub enum Event {
    EventUp,
    EventDown,
    EventMove(i32, i32),
    // The above are more specifically EventMotion, but to prevent a breaking
    // change I did not rename them, but instead made EventKey** --kmcg3413@gmail.com
    EventKeyUp,
    EventKeyDown,
    InitWindow,
    SaveState,
    TermWindow,
    GainedFocus,
    LostFocus,
    InputChanged,
    WindowResized,
    WindowRedrawNeeded,
    ContentRectChanged,
    ConfigChanged,
    LowMemory,
    Start,
    Resume,
    Pause,
    Stop,
    Destroy,
}

#[cfg(not(target_os = "android"))]
use this_platform_is_not_supported;

#[macro_export]
macro_rules! android_start(
    ($main: ident) => (
        pub mod __android_start {
            extern crate android_glue;
            use std::mem::transmute;

            // this function is here because we are sure that it will be included by the linker
            // so we call app_dummy in it, in order to be sure that the native glue will be included
            #[start]
            pub fn start(_: isize, _: *const *const u8) -> isize {
                unsafe { android_glue::ffi::app_dummy() };
                1
            }


            #[no_mangle]
            #[inline(never)]
            #[allow(non_snake_case)]
            pub extern "C" fn android_main(app: usize) {
                android_glue::android_main2(unsafe { transmute(app) }, move|| super::$main());
            }
        }
    )
);

/// Return a reference to the application structure.
pub fn get_app() -> Arc<ActivityState> {
    let mut pullout: Option<Option<Arc<ActivityState>>> = Option::None;
    ANDROID_APP.with( | tls | {
        pullout = Option::Some(tls.borrow_mut().clone());
    });

    pullout.unwrap().expect("This thread not properly initialized to access activity state!")
}

/// This is the function that must be called by `android_main`
#[doc(hidden)]
pub fn android_main2<F>(app: Arc<ActivityState>, main_function: F)
    where F: FnOnce(), F: 'static, F: Send
{
    use std::{mem, ptr};

    write_log("[android_main2] entered");

    // Set the value for the thread local storage for this thread.
    ANDROID_APP.with( | tls | {
        *tls.borrow_mut() = Option::Some(app.clone());
    });

    app.setonappcmd(commands_callback);
    app.setoninputevent(inputs_callback);
    *app.userdata.lock().unwrap() = Box::new(Arc::new(Context {
        senders:        Mutex::new(Vec::new()),
        missed:         Mutex::new(Vec::new()),
        missedcnt:      AtomicUsize::new(0),
        userdata:       Mutex::new(Box::new(())),
        mustdestroy:    AtomicBool::new(false),
    }));

    let context = app.userdata.lock().unwrap()
                    .downcast_ref::<Arc<Context>>()
                    .cloned().unwrap();

    // Set our stdout and stderr so that panics are directed to the log.
    std::io::set_print(Box::new(ToLogWriter));
    std::io::set_panic(Box::new(ToLogWriter));

    let (mtx, mrx) = channel::<()>();
    let appcloned = app.clone();
    // executing the main function in parallel
    std::thread::spawn(move || {
        // Set the thread local storage for the activity state.
        ANDROID_APP.with( | tls | {
            *tls.borrow_mut() = Option::Some(appcloned);
        });            
        std::io::set_print(Box::new(ToLogWriter));
        std::io::set_panic(Box::new(ToLogWriter));
        main_function();
        println!("[android_main2] telling looper thread to exit..");
        mtx.send(()).unwrap();
        // Wake the looper thread so it can see we have terminated.
        get_app().cmdpipe.write(ffi::APP_CMD_NULL as i8);
        ANDROID_APP.with( | tls | {
            *tls.borrow_mut() = Option::None;
        });            
    });

    let mut appthreadexited: bool = false;

    // Polling for events forever, until shutdown signal is set.
    // note: that this must be done in the same thread as android_main because 
    //       ALooper are thread-local
    let mut events: libc::c_int;
    let mut source: *mut libc::c_void;
    loop {
        events = 0;
        source = 0 as *mut libc::c_void;

        // A `-1` means to block forever, but any other positive value 
        // specifies the number of milliseconds to block for, before
        // returning.
        println!("[!looper] polling all");
        let ident: libc::c_int = unsafe { ffi::ALooper_pollAll(
            -1, ptr::null_mut(), &mut events, &mut source
        ) }; 
        println!("[!looper] returned");

        // If the application thread has exited then we need to exit also.
        if mrx.try_recv().is_ok() {
            println!("[looper-thread] detected main thread exit");
            appthreadexited = true;
        }

        if appthreadexited && context.mustdestroy.load(Ordering::Relaxed) {
            println!("[looper-thread] thread dead and destroy event found - exiting");
            break;
        }

        // processing the event
        if !source.is_null() {
            println!("[looper-thread] ident:{} source:{:p} executing manual callback", ident, source);
            let source: *mut AndroidPollSource = unsafe { mem::transmute(source) };
            unsafe { (*source).callprocess(app.clone()) };
        }
    }

    ANDROID_APP.with( | tls | {
        *tls.borrow_mut() = Option::None;
    });
}

/// Writer that will redirect what is written to it to the logs.
struct ToLogWriter;

impl Write for ToLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let message = CString::new(buf).unwrap();
        let tag = CString::new("RustAndroidGlueLowLevel").unwrap();
        let tag = tag.as_ptr();
        unsafe { ffi::__android_log_write(3, tag, message.as_ptr()) };
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Send a event to anything that has registered a sender. This is where events
/// messages are sent, and the main application can recieve them from this. There
/// is likely only one sender in our list, but we support more than one.
fn send_event(event: Event) {
    let ctx = get_context();
    let senders = ctx.senders.lock().ok().unwrap();

    // Store missed events up to a maximum.
    if senders.len() < 1 {
        // We use a quick target word sized atomic load to check
        if ctx.missedcnt.load(Ordering::SeqCst) < MISSEDMAX {
            let mut missed = ctx.missed.lock().unwrap();
            missed.push(event);
            ctx.missedcnt.fetch_add(1, Ordering::SeqCst);
        }
    }

    for sender in senders.iter() {
        sender.send(event).unwrap();
    }
}

/// The callback for input.
///
/// This callback is registered when we startup and is called by our main thread,
/// from the function `android_main2`. We then process the event to gain additional
/// information, and finally send the event, which normally would be recieved by
/// the main application thread IF it has registered a sender. 
pub fn inputs_callback(_: Arc<ActivityState>, event: InputEvent) -> libc::int32_t
{
    // I would like to replace all these unsafe calls, by implementing the
    // features into InputEvent, so it will provide a safe interface, but
    // at the moment I have not implemented anything for InputEvent, so we
    // have to grab the raw pointer and call the unsafe FFI interface.
    let rawevent = event.getptr();

    println!("[inputs_callback] got input event");

    fn get_xy(event: *const ffi::AInputEvent) -> (i32, i32) {
        let x = unsafe { ffi::AMotionEvent_getX(event, 0) };
        let y = unsafe { ffi::AMotionEvent_getY(event, 0) };
        (x as i32, y as i32)
    }

    let etype = unsafe { ffi::AInputEvent_getType(rawevent) };
    let action = unsafe { ffi::AMotionEvent_getAction(rawevent) };
    let action_code = action & ffi::AMOTION_EVENT_ACTION_MASK;

    println!("[inputs_callback] etype:{} action:{} action_code:{}", etype, action, action_code);

    match etype {
        ffi::AINPUT_EVENT_TYPE_KEY => match action_code {
            ffi::AKEY_EVENT_ACTION_DOWN => { send_event(Event::EventKeyDown); },
            ffi::AKEY_EVENT_ACTION_UP => send_event(Event::EventKeyUp),
            _ => write_log(&format!("unknown input-event-type:{} action_code:{}", etype, action_code)),
        },
        ffi::AINPUT_EVENT_TYPE_MOTION => match action_code {
            ffi::AMOTION_EVENT_ACTION_UP
                | ffi::AMOTION_EVENT_ACTION_OUTSIDE
                | ffi::AMOTION_EVENT_ACTION_CANCEL
                | ffi::AMOTION_EVENT_ACTION_POINTER_UP =>
            {
                send_event(Event::EventUp);
            },
            ffi::AMOTION_EVENT_ACTION_DOWN
                | ffi::AMOTION_EVENT_ACTION_POINTER_DOWN =>
            {
                let (x, y) = get_xy(rawevent);
                send_event(Event::EventMove(x, y));
                send_event(Event::EventDown);
            },
            _ => {
                let (x, y) = get_xy(rawevent);
                send_event(Event::EventMove(x, y));
            },
        },
        _ => write_log(&format!("unknown input-event-type:{} action_code:{}", etype, action_code)),
    }
    0
}

/// The callback for commands.
#[doc(hidden)]
pub fn commands_callback(_: Arc<ActivityState>, command: libc::int32_t) {
    match command {
        ffi::APP_CMD_INIT_WINDOW => send_event(Event::InitWindow),
        ffi::APP_CMD_SAVE_STATE => send_event(Event::SaveState),
        ffi::APP_CMD_TERM_WINDOW => send_event(Event::TermWindow),
        ffi::APP_CMD_GAINED_FOCUS => send_event(Event::GainedFocus),
        ffi::APP_CMD_LOST_FOCUS => send_event(Event::LostFocus),
        ffi::APP_CMD_INPUT_CHANGED => send_event(Event::InputChanged),
        ffi::APP_CMD_WINDOW_RESIZED => send_event(Event::WindowResized),
        ffi::APP_CMD_WINDOW_REDRAW_NEEDED => send_event(Event::WindowRedrawNeeded),
        ffi::APP_CMD_CONTENT_RECT_CHANGED => send_event(Event::ContentRectChanged),
        ffi::APP_CMD_CONFIG_CHANGED => send_event(Event::ConfigChanged),
        ffi::APP_CMD_LOW_MEMORY => send_event(Event::LowMemory),
        ffi::APP_CMD_START => send_event(Event::Start),
        ffi::APP_CMD_RESUME => send_event(Event::Resume),
        ffi::APP_CMD_PAUSE => send_event(Event::Pause),
        ffi::APP_CMD_STOP => send_event(Event::Stop),
        ffi::APP_CMD_DESTROY => {
            let context = get_context();
            send_event(Event::Destroy);
            context.mustdestroy.store(true, Ordering::Relaxed);
        },
        ffi::APP_CMD_NULL => {
            // Do not do anything. Unless, we want to do something. This
            // is currently used to wake the looper so it can see that
            // the main thread has died.
        },
        _ => write_log(&format!("unknown command {}", command)),
    }
}

/// Returns the current Context.
fn get_context() -> Arc<Context> {
    let astate = get_app();
    // I do not like this, but it keeps from breaking existing code.
    let ud = astate.userdata.lock().unwrap();
    ud.downcast_ref::<Arc<Context>>().expect("no context in activity state").clone()
}

/// Adds a sender where events will be sent to.
pub fn add_sender(sender: Sender<Event>) {
    let ctx = get_context();
    ctx.senders.lock().unwrap().push(sender);
}

/// Adds a sender where events will be sent to, but also sends
/// any missing events to the sender object. 
///
/// The missing events happen when the application starts, but before
/// any senders are registered. Since these might be important to certain
/// applications, this function provides that support.
pub fn add_sender_missing(sender: Sender<Event>) {
    let ctx = get_context();
    let mut senders = ctx.senders.lock().ok().unwrap();

    if senders.len() == 0 {
        // If the first sender added then, let us send any missing events.
        let mut missed = ctx.missed.lock().unwrap();
        while missed.len() > 0 {
            sender.send(missed.remove(0)).unwrap();
        }
        ctx.missedcnt.store(0, Ordering::Relaxed);
    }

    senders.push(sender);
}

/// Returns a handle to the native window.
pub unsafe fn get_native_window() -> ffi::NativeWindowType {
    let astate = get_app();

    loop {
        let safewin = astate.window.lock().unwrap();

        if safewin.is_some() {
            return safewin.as_ref().unwrap().getptr();
        }

        // spin-locking
        schedule_recv::oneshot_ms(10);
    }
}

/// 
pub fn write_log(message: &str) {
    let message = CString::new(message.as_bytes()).unwrap();
    let message = message.as_ptr();
    let tag = CString::new("RustAndroidGlueStdouterr").unwrap();
    let tag = tag.as_ptr();
    unsafe { ffi::__android_log_write(3, tag, message) };
}

pub enum AssetError {
    AssetMissing,
    EmptyBuffer,
}

pub fn load_asset(filename: &str) -> Result<Vec<u8>, AssetError> {
    struct AssetCloser {
        asset: *mut ffi::Asset,
    }

    impl Drop for AssetCloser {
        fn drop(&mut self) {
            unsafe {
                ffi::AAsset_close(self.asset)
            };
        }
    }

    unsafe fn get_asset_manager() -> *mut ffi::AAssetManager {
        let app = get_app();
        (*(app.activity)).assetManager

        //let app = &*ANDROID_APP;
        //let activity = &*app.activity;
        //activity.assetManager
    }

    let filename_c_str = CString::new(filename.as_bytes()).unwrap();
    let filename_c_str = filename_c_str.as_ptr();
    let asset = unsafe {
        ffi::AAssetManager_open(
            get_asset_manager(), filename_c_str, ffi::MODE_STREAMING)
    };
    if asset.is_null() {
        return Err(AssetError::AssetMissing);
    }
    let _asset_closer = AssetCloser{asset: asset};
    let len = unsafe {
        ffi::AAsset_getLength(asset)
    };
    let buff = unsafe {
        ffi::AAsset_getBuffer(asset)
    };
    if buff.is_null() {
        return Err(AssetError::EmptyBuffer);
    }
    let vec = unsafe {
        Vec::from_raw_buf(buff as *const u8, len as usize)
    };
    Ok(vec)
}