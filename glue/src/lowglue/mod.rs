//!
//! This module contains the low-level glue. This is essentially what the form 
//! that the ported C code took. It also wraps some raw pointers to form a safe
//! object where API methods for that object are made safe. This makes the NDK
//! more Rust friendly.
//!
use std::ffi::CString;
use std;
use std::sync::Arc;
use std::mem::{transmute, zeroed, forget};
use std::sync::Mutex;
use std::sync::atomic::{AtomicIsize, AtomicBool, Ordering, AtomicPtr};
use std::time::Duration;

pub use super::write_log;
pub use super::libc;

pub use self::wraps::InputEvent;
pub use self::wraps::Configuration;
pub use self::wraps::Looper;
pub use self::wraps::InputQueue;
pub use self::wraps::Window;
pub use self::wraps::Rect;
pub use self::wraps::NativeActivity;
pub use self::wraps::NativeWindow;
pub use self::wraps::LooperCallbackData;
pub use self::activitystate::ActivityState;
pub use self::activitystate::AndroidPollSource;
pub use self::activitystate::MutexWait;
pub use self::unixpipe::StaticTypeUnixPipe;
pub use self::unixpipe::UnixPipe;

pub use super::ffi;

pub mod wraps;
pub mod activitystate;
pub mod unixpipe;

extern "C" { 
    #[allow(improper_ctypes)]
    pub fn android_main(astate: *mut libc::c_void);
}

#[allow(non_snake_case)]
extern "C" fn onDestroy(activity: *mut ffi::ANativeActivity) {
    unsafe {
        write_log("[ondestroy] called");
        let astate: Arc<ActivityState> = transmute((*activity).instance);
        if astate.callondestroy(&astate) == 1 {
            return;
        }
        astate.cmdpipe.write(ffi::APP_CMD_DESTROY as i8);
        let mut l = astate.destroyed.lock().unwrap();
        loop {
            // It may already be set. So in this case we do not need
            // to wait around. Let us just exit the loop.
            if *l {
                break;
            }
            let result = astate.destroyed.wait_timeout(l, Duration::seconds(4)).unwrap();
            l = result.0;
            if !result.1 {
                // Try to notify the application developer that for some
                // reason they are not handling this situation properly.
                write_log("[ondestroy] not being handled in a timely manner!");
            }
        }

        // This is the end. We need to drop our Arc<ActivityState>.
        (*activity).instance = 0 as *mut libc::c_void;
        // forget(astate); <--- Do _not_ do this, else it will not drop.
        // Anyone else holding a copy will keep it alive in the heap, until
        // they are done using it themselves.
        println!("[ondestroy] activity considered dead");
    }
}
#[allow(non_snake_case)]
extern "C" fn onStart(activity: *mut ffi::ANativeActivity) {
    unsafe {
        write_log("[onstart] called");
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        if astate.callonstart(astate) == 1 {
            return;
        }
        set_activity_state(astate, ffi::APP_CMD_START as i8);
    }
}
#[allow(non_snake_case)]
extern "C" fn onResume(activity: *mut ffi::ANativeActivity) {
    unsafe {
        write_log("[onresume] called");
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        if astate.callonresume(&astate) == 1 {
            return;
        }

        set_activity_state(astate, ffi::APP_CMD_RESUME as i8);
    }
}
#[allow(non_snake_case)]
extern "C" fn onSaveInstanceState(activity: *mut ffi::ANativeActivity, outlen: *mut libc::size_t) -> *mut libc::c_void {
    unsafe {
        write_log("[onsaveinstancestate] called");

        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);

        let cbresult = astate.callonsaveinstancestate(astate);

        let mut lock = astate.statesaved.lock().unwrap();
        *lock = false;
        astate.cmdpipe.write(ffi::APP_CMD_SAVE_STATE as i8);
        while !*lock {
            lock = astate.statesaved.wait(lock).unwrap();
        }

        let mut sslock = astate.savedstate.lock().unwrap();
        if sslock.is_none() || (cbresult.0 == 1 && cbresult.1.is_none()) {
            // No state was specified to be saved.
            *outlen = 0;
            return 0 as *mut libc::c_void;
        }

        // We do have state specified to be saved.
        let v = if cbresult.0 == 1 && cbresult.1.is_some() {
            cbresult.1
        } else {
            sslock.take()
        };

        // No Vec<u8>, just Option::None.
        if v.is_none() {
            *outlen = 0;
            return 0 as *mut libc::c_void;
        }

        // Get the Vec<u8>.
        let v = v.unwrap();

        // We have a funny situation. It seems that the system will call `free`.
        // I am not entirely sure, but if it does, we need to make sure that the
        // vector `v` does not drop its own allocation. At least this appeared to
        // be what the original code was doing.

        let ptr: *const u8 = v.as_slice().as_ptr();

        if v.len() > 0xffffffff {
            panic!("saved state can only be 32-bit in length!");
        }

        *outlen = v.len() as u32;

        // Just forgot about calling the deconstructor. Hopefully, the system
        // will free the memory.. -- kmcg
        // WARNING: NEED CONFIRMATION
        forget(v);
        
        return transmute(ptr);
    }
}
#[allow(non_snake_case)]
extern "C" fn onPause(activity: *mut ffi::ANativeActivity) {
    unsafe {
        println!("[onpause] called activity:{:p}", activity);
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        println!("[onpause] looking at callback");
        if astate.callonpause(astate) == 1 {
            println!("[onpause] calling callback");
            return;
        }
        println!("[onpause] calling set_activity_state");
        set_activity_state(astate, ffi::APP_CMD_PAUSE as i8);
    }
}
#[allow(non_snake_case)]
extern "C" fn onStop(activity: *mut ffi::ANativeActivity) {
    unsafe {
        write_log("[onstop] called");
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        if astate.callonstop(astate) == 1 {
            return;
        }

        set_activity_state(astate, ffi::APP_CMD_STOP as i8);
    }
}
#[allow(non_snake_case)]
extern "C" fn onConfigurationChanged(activity: *mut ffi::ANativeActivity) {
    unsafe {
        write_log("[onconfigurationchanged] called");
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        if astate.callonconfigurationchanged(astate) == 1 {
            return;
        }

        astate.cmdpipe.write(ffi::APP_CMD_CONFIG_CHANGED as i8);
    }
}
#[allow(non_snake_case)]
extern "C" fn onLowMemory(activity: *mut ffi::ANativeActivity) {
    unsafe {
        write_log("[onlowmemory] called");
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        if astate.callonlowmemory(astate) == 1 {
            return;
        }

        astate.cmdpipe.write(ffi::APP_CMD_LOW_MEMORY as i8);
    }
}
#[allow(non_snake_case)]
extern "C" fn onWindowFocusChanged(activity: *mut ffi::ANativeActivity, focused: libc::c_int) {
    unsafe {
        write_log("[onwindowfocuschanged] called");
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        if astate.callonwindowfocuschanged(astate, focused) == 1 {
            return;
        }
        if focused > 0 {
            astate.cmdpipe.write(ffi::APP_CMD_GAINED_FOCUS as i8);
        } else {
            astate.cmdpipe.write(ffi::APP_CMD_LOST_FOCUS as i8);
        }
    }
}
#[allow(non_snake_case)]
extern "C" fn onNativeWindowCreated(activity: *mut ffi::ANativeActivity, window: *mut ffi::ANativeWindow) {
    unsafe {
        write_log("[onnativewindowcreated] called");
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        if astate.callonnativewindowcreated(astate, &NativeWindow::wrap(window)) == 1 {
            return;
        }
        set_window(astate, NativeWindow::wrap(window), true);
    }
}
#[allow(non_snake_case)]
extern "C" fn onNativeWindowDestroyed(activity: *mut ffi::ANativeActivity, window: *mut ffi::ANativeWindow) {
    unsafe {
        println!("[onnativewindowdestroyed] called window:{:p}", window);
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        if astate.callonnativewindowdestroyed(astate, &NativeWindow::wrap(window)) == 1 {
            return;
        }
        set_window(astate, NativeWindow::wrap(window), false);
    }
}
#[allow(non_snake_case)]
extern "C" fn onInputQueueCreated(activity: *mut ffi::ANativeActivity, queue: *mut ffi::AInputQueue) {
    unsafe {
        write_log("[oninputqueuecreated] called");
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        // Check if callback wants to filter event.
        if astate.calloninputqueuecreated(astate, &InputQueue::wrap(queue)) == 1 {
            return;
        }    
        set_input(astate, transmute(queue), true);
    }
}
#[allow(non_snake_case)]
extern "C" fn onInputQueueDestroyed(activity: *mut ffi::ANativeActivity, queue: *mut ffi::AInputQueue) {
    unsafe {
        write_log("[oninputqueuedestroyed] called");
        let astate: &Arc<ActivityState> = transmute(&(*activity).instance);
        // Check if callback wants to filter event.
        if astate.calloninputqueuedestroyed(astate, &InputQueue::wrap(queue)) == 1 {
            return;
        }
        set_input(astate, InputQueue::wrap(queue), false);
    }
}

fn set_window(astate: &Arc<ActivityState>, window: NativeWindow, created: bool) {
    println!("[set_window] locking pending window");
    let mut l = astate.pendingwindow.lock().unwrap();
    loop {
        if l.is_none() {
            break;
        }
        println!("[set_window] pending window wait");
        l = astate.pendingwindow.wait(l).unwrap();
    }

    *l = Option::Some((created, window));

    if created {
        println!("[set_window] write init window command");
        astate.cmdpipe.write(ffi::APP_CMD_INIT_WINDOW as i8); 
    } else {
        println!("[set_window] write term window command");
        astate.cmdpipe.write(ffi::APP_CMD_TERM_WINDOW as i8);
    }

    // Be nice and wake anyone else who is waiting.
    println!("[set_window] pending window notify all");
    astate.pendingwindow.notify_all();

    println!("[set_window] waiting for pending window to be none");
    loop {
        println!("[set_window] checking..");
        if l.is_none() {
            break;
        }
        let result = astate.pendingwindow.wait(l).unwrap();
        l = result;
    }

    println!("[set_window] pending window was none");
}

/// We wait until `pendinginputqueue` has been consumed, then we set it, and
/// finally we wait until it has been consumed.
fn set_input(astate: &Arc<ActivityState>, queue: InputQueue, created: bool) {
    write_log("[setinput] trying to lock pending-input-queue");
    let mut l = astate.pendinginputqueue.lock().unwrap();
    write_log("[setinput] locked");
    loop {
        if l.is_none() {
            break;
        }
        write_log("[setinput] waiting for previous input queue to be handled");
        l = astate.pendinginputqueue.wait(l).unwrap();
    }

    *l = Option::Some((created, queue));

    write_log("[setinput] writing to command pipe");
    astate.cmdpipe.write(ffi::APP_CMD_INPUT_CHANGED as i8);

    // Be nice and wake anyone else who is waiting.
    astate.pendinginputqueue.notify_all();

    write_log("[setinput] waiting for acknowledgement");
    loop {
        if l.is_none() {
            write_log("[setinput] got acknowledgement"); 
            break;
        }
        l = astate.pendinginputqueue.wait(l).unwrap();
    }
}

pub fn set_activity_state(astate: &Arc<ActivityState>, cmd: i8) {
    println!("[set_activity_state] cmd:{}", cmd);
    astate.cmdpipe.write(cmd);
    let mut lock = astate.activitystate.lock().unwrap();
    while *lock != cmd as isize {
        println!("[set_activity_state] wait");
        lock = astate.activitystate.wait(lock).unwrap();
    }
}

fn dummy_onappcmd(_activity: Arc<ActivityState>, _cmd: libc::int32_t) {}
fn dummy_oninputevent(_activity: Arc<ActivityState>, _event: InputEvent) -> libc::int32_t {0}

/// This was exported by the old C version of the code.
#[no_mangle]
pub unsafe extern "C" fn app_dummy() {
}

pub fn looper_entry(astate: Arc<ActivityState>) {
    unsafe {
        write_log("[looper-thread] started");
        // Setup asset manager.
        {
            let cfglock = astate.config.lock().unwrap();
            if cfglock.is_some() {
                ffi::AConfiguration_fromAssetManager(
                    cfglock.as_ref().unwrap().getptr(),
                    (*astate.activity).assetManager
                );
            }
        }
        // Setup the looper.
        let looper = ffi::ALooper_prepare(ffi::ALOOPER_PREPARE_ALLOW_NON_CALLBACKS);
        ffi::ALooper_addFd(looper, astate.cmdpipe.pipe.getrdfd(), ffi::LOOPER_ID_MAIN, ffi::ALOOPER_EVENT_INPUT, transmute(0), transmute(&astate.cmdpollsource));
        let looper = Looper::wrap(looper);
        *(astate.looper.lock().unwrap()) = Option::Some(looper);
        astate.running.store(true, Ordering::Relaxed);
        // Call main application function.
        write_log("[looper-thread] calling android_main");
        android_main(transmute::<Arc<ActivityState>, *mut libc::c_void>(astate.clone()));
        // If we return, we need to set our state as destroyed. If the
        // application spawned threads that are still running then they
        // will be killed by the OS when it desires. So they are on their
        // own as far as we are concerned. If the application desired to
        // properly handle this then it needs to be written to do so. The
        // best way would be for us to implement (if not already done) a
        // more appropriate interface for signaling not to automatically 
        // do this here, or support a different startup function that can
        // let us know to do this or not to do this.
        *astate.destroyed.lock().unwrap() = true;
        // Just incase it is waiting for this to happen.
        astate.destroyed.notify_all();        
    }
}

/// The standard processor for input.
///
/// Will call the function set by 'ActivityState::setonappcmd`, but may do
/// additional work before and after the call.
pub fn process_input(astate: Arc<ActivityState>) {
    unsafe {
        println!("[process_input] called");
        let event: *mut ffi::AInputEvent = zeroed();
        // I thought about it. We can be sure that no system thread which changes the input queue
        // will exit if we hold this lock. I am not sure if that is best, but it does seem like 
        // the safest idea, at this time. It also prevents someone else from coming in and changing
        // it and thinking the change will immediantly take effect, so that too is safe. -- kmcg3413
        //
        // The alternative is to grab it, clone it, and unlock it...
        let lock = astate.inputqueue.lock().unwrap();
        {
            let inputqueue = lock.as_ref().unwrap().clone();
            while ffi::AInputQueue_getEvent(inputqueue.getptr(), transmute(&event)) >= 0 {
                if ffi::AInputQueue_preDispatchEvent(inputqueue.getptr(), event) > 0 {
                    continue;
                }
                let handled = astate.calloninputevent(astate.clone(), InputEvent::wrap(event));
                ffi::AInputQueue_finishEvent(inputqueue.getptr(), event, handled);
            }
        }
        // I am paranoid it will drop the lock before here, without the explicit drop.
        drop(lock);
    }
}


/// The process command post processor.
///
/// This is called inside of `process_cmd` before calling `ActivityState::setoninputevent`.
///
/// It is left here, public and callable, in the event that you implement your own
/// `process_cmd`.
pub fn process_cmd_pre(astate: &Arc<ActivityState>, cmd: i8) {
    unsafe {
        match cmd as i32 {
            ffi::APP_CMD_INPUT_CHANGED => {
                let mut lock = astate.inputqueue.lock().unwrap();
                let mut pendlock = astate.pendinginputqueue.lock().unwrap();
                // If we currently had a valid inputqueue type, then detach
                // it since we was likely attached.
                if lock.is_some() {
                    println!("[process_cmd_pre] old input queue detached");
                    ffi::AInputQueue_detachLooper(lock.as_ref().unwrap().getptr());
                }

                // Take the inputqueue type out of the option, leaving a None.
                let newtup = pendlock.take().unwrap();
                let created = newtup.0;
                let newinputqueue = newtup.1;

                if created {
                    println!("[process_cmd_pre] attached new input queue");
                    ffi::AInputQueue_attachLooper(
                        newinputqueue.getptr(),
                        astate.looper.lock().unwrap().as_ref().unwrap().getptr(),
                        ffi::LOOPER_ID_INPUT,
                        transmute(0),
                        transmute(&astate.inputpollsource)
                    );
                    *lock = Option::Some(newinputqueue);
                } else {
                    println!("[process_cmd_pre] no new input queue attached");
                    *lock = Option::None;
                }

                // The system thread should be sleeping, since we were able to grab the
                // `pendlock` above. So let us wake it up and let it check that we have
                // taken the inputqueue type so that it can return back to the system.
                astate.pendinginputqueue.notify_all();
                astate.inputqueue.notify_all();
                // Any thread waiting for the notify should not wake until we drop the
                // `pendlock`, which may happen before or after the `notify_all` call.
            },
            ffi::APP_CMD_INIT_WINDOW => {
                let mut lock = astate.window.lock().unwrap();
                let mut pendlock = astate.pendingwindow.lock().unwrap();
                *lock = match pendlock.take() {
                    Some(tup) => Option::Some(tup.1),
                    None => Option::None,
                };
                astate.pendingwindow.notify_all();
                astate.window.notify_all();
            },
            ffi::APP_CMD_TERM_WINDOW => {
                astate.window.notify_all();
            },
            ffi::APP_CMD_RESUME | ffi::APP_CMD_START |
            ffi::APP_CMD_PAUSE | ffi::APP_CMD_STOP => {
                *astate.activitystate.lock().unwrap() = cmd as isize;
                // Let anyone who was listening know the state changed.
                astate.activitystate.notify_all();
            },
            ffi::APP_CMD_CONFIG_CHANGED => {
                ffi::AConfiguration_fromAssetManager(
                    astate.config.lock().unwrap().as_ref().unwrap().getptr(),
                    (*(astate.activity)).assetManager
                );
            },
            ffi::APP_CMD_DESTROY => {
                astate.destroyrequested.store(true, Ordering::Relaxed);
            }
            _ => {},
        }
    }
}

/// The process command post processor.
///
/// This is called inside of `process_cmd` after calling `ActivityState::setoninputevent`.
///
/// It is left here, public and callable, in the event that you implement your own
/// `process_cmd`.
pub fn process_cmd_post(astate: &Arc<ActivityState>, cmd: i8) {
    match cmd as i32 {
        ffi::APP_CMD_TERM_WINDOW => {
            println!("[process_cmd_post] term window handling");
            // By setting this we allow the system thread to exit.
            *astate.pendingwindow.lock().unwrap() = Option::None;
            println!("[process_cmd_post] trying to clear window");
            // Also denote we have no window by clearing it.
            *astate.window.lock().unwrap() = Option::None;
            println!("[process_cmd_post] notifying all");
            // This is just a nice gesture for anyone listening.
            astate.window.notify_all();
            // This wakes the now sleeping system thread.
            astate.pendingwindow.notify_all();
        },
        ffi::APP_CMD_SAVE_STATE => {
            *astate.statesaved.lock().unwrap() = true;
            astate.statesaved.notify_all();
        },
        ffi::APP_CMD_RESUME => {
            *astate.savedstate.lock().unwrap() = Option::None;
        },
        _ => {},
    }
}

/// The standard processor for commands.
///
/// This will call the function set by `ActivityState::setoninputevent`, but 
/// may do additional work before and after the call.
pub fn process_cmd(astate: Arc<ActivityState>) {
    println!("[process_cmd] called");
    let cmd = astate.cmdpipe.read();
    println!("[process_cmd] cmd:{}", cmd);
    process_cmd_pre(&astate, cmd);
    println!("[process_cmd] calling onappcmd");
    astate.callonappcmd(astate.clone(), cmd as i32);
    println!("[process_cmd] doing post work");
    process_cmd_post(&astate, cmd);
}

/// The binary entry point, which is called by the system on activity creation and start.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "C" fn ANativeActivity_onCreate(activity: *mut ffi::ANativeActivity, savedstate: *mut u8, savedstatesize: libc::size_t) {
    write_log("[system-thread] booting");
    (*(*activity).callbacks).onDestroy = onDestroy;
    (*(*activity).callbacks).onStart = onStart;
    (*(*activity).callbacks).onResume = onResume;
    (*(*activity).callbacks).onSaveInstanceState = onSaveInstanceState;
    (*(*activity).callbacks).onPause = onPause;
    (*(*activity).callbacks).onStop = onStop;
    (*(*activity).callbacks).onConfigurationChanged = onConfigurationChanged;
    (*(*activity).callbacks).onLowMemory = onLowMemory;
    (*(*activity).callbacks).onWindowFocusChanged = onWindowFocusChanged;
    (*(*activity).callbacks).onNativeWindowCreated = onNativeWindowCreated;
    (*(*activity).callbacks).onNativeWindowDestroyed = onNativeWindowDestroyed;
    (*(*activity).callbacks).onInputQueueCreated = onInputQueueCreated;
    (*(*activity).callbacks).onInputQueueDestroyed = onInputQueueDestroyed;

    // Package it up into a safe form.
    let savedstate: Vec<u8> = Vec::from_raw_parts(savedstate, savedstatesize as usize, savedstatesize as usize);

    let cmdpollsource = AndroidPollSource {
        id:         AtomicIsize::new(ffi::LOOPER_ID_MAIN as isize),
        process:    AtomicPtr::new(0 as *mut ()),
    };
    cmdpollsource.setprocess(process_cmd);

    let inputpollsource = AndroidPollSource {
        id:         AtomicIsize::new(ffi::LOOPER_ID_MAIN as isize),
        process:    AtomicPtr::new(0 as *mut ()),
    };
    inputpollsource.setprocess(process_input);

    let state: Arc<ActivityState> = Arc::new(ActivityState {
        userdata:                   Mutex::new(Box::new(())),
        //
        oninputqueuedestroyed:      AtomicPtr::new(0 as *mut ()),
        oninputqueuecreated:        AtomicPtr::new(0 as *mut ()),
        onnativewindowdestroyed:    AtomicPtr::new(0 as *mut ()),
        onnativewindowcreated:      AtomicPtr::new(0 as *mut ()),
        onwindowfocuschanged:       AtomicPtr::new(0 as *mut ()),
        onlowmemory:                AtomicPtr::new(0 as *mut ()),
        onconfigurationchanged:     AtomicPtr::new(0 as *mut ()),
        onstop:                     AtomicPtr::new(0 as *mut ()),
        onpause:                    AtomicPtr::new(0 as *mut ()),
        onsaveinstancestate:        AtomicPtr::new(0 as *mut ()),
        onresume:                   AtomicPtr::new(0 as *mut ()),
        onstart:                    AtomicPtr::new(0 as *mut ()),
        ondestroy:                  AtomicPtr::new(0 as *mut ()),
        // This is set below.
        onappcmd:           AtomicPtr::new(0 as *mut ()),
        // This is set below.
        oninputevent:       AtomicPtr::new(0 as *mut ()),
        activity:           transmute(activity),
        config:             MutexWait::new(Option::None, "config"),
        savedstate:         MutexWait::new(Option::Some(savedstate), "savedstate"),
        looper:             MutexWait::new(Option::None, "looper"),
        inputqueue:         MutexWait::new(Option::None, "inputqueue"),
        window:             MutexWait::new(Option::None, "window"),
        contentrect:        MutexWait::new(Option::None, "contentrect"),
        activitystate:      MutexWait::new(0, "activitystate"),
        destroyrequested:   AtomicBool::new(false),
        running:            AtomicBool::new(false),
        statesaved:         MutexWait::new(false, "statesaved"),
        destroyed:          MutexWait::new(false, "destroyed"),
        redrawneeded:       AtomicBool::new(false),
        // The command interface which is compatible with original code.
        cmdpipe:            StaticTypeUnixPipe::wrap(UnixPipe::new()),
        pendinginputqueue:  MutexWait::new(Option::None, "pendinginputqueue"),
        pendingwindow:      MutexWait::new(Option::None, "pendingwindow"),
        // A little nasty looking, but at least we anchor the allocation to this structure.
        cmdpollsource:      cmdpollsource,
        inputpollsource:    inputpollsource,
    });

    // These are the highest level callbacks, and were originally provided by
    // the C framework. We need to initialize them to something valid here.
    state.setonappcmd(dummy_onappcmd);
    state.setoninputevent(dummy_oninputevent);

    // Spawn looper thread.
    let statecloned = state.clone();
    std::thread::spawn(move || { looper_entry(statecloned); } );

    //
    (*activity).instance = transmute(state);

    write_log("[system-thread] booted");

    std::old_io::stdio::set_stdout(box std::old_io::LineBufferedWriter::new(ToLogWriter));
    std::old_io::stdio::set_stderr(box std::old_io::LineBufferedWriter::new(ToLogWriter));    
}

/// Writer that will redirect what is written to it to the logs.
struct ToLogWriter;

impl Writer for ToLogWriter {
    fn write_all(&mut self, buf: &[u8]) -> std::old_io::IoResult<()> {
        let message = CString::new(buf).unwrap();
        let message = message.as_ptr();
        let tag = b"RustAndroidGlueLowLevel";
        let tag = CString::new(tag).unwrap();
        let tag = tag.as_ptr();
        unsafe { ffi::__android_log_write(3, tag, message) };
        Ok(())
    }
}