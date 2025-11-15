//! This module handles the registration and management of external engines for the FiSH IRC client.

use std::collections::HashMap;
use std::ffi::{CStr, CString};

use log::{error, info, trace, warn};
use parking_lot::{Mutex, RwLock};

use crate::FISH_INJECT_ENGINE_VERSION;
// C structure definition provided by engines
#[repr(C)]
pub struct FishInjectEngine {
    pub version: u32,
    pub engine_name: *const i8,
    // True if engine should run *after* others callback for outgoing IRC lines (before encryption/sending)
    pub is_postprocessor: bool,

    // Args: socket_id (u32), line (*const i8 UTF-8), line_len (usize)
    // Returns: *mut i8 (new UTF-8 line, must be freed by Inject DLL via free_string) or NULL if unchanged
    pub on_outgoing_irc_line: unsafe extern "C" fn(u32, *const i8, usize) -> *mut i8,

    // Callback for incoming IRC lines (after receiving/decryption)
    // Args: socket_id (u32), line (*const i8 UTF-8), line_len (usize)
    // Returns: *mut i8 (new UTF-8 line, must be freed via free_string) or NULL if unchanged
    pub on_incoming_irc_line: unsafe extern "C" fn(u32, *const i8, usize) -> *mut i8,

    // Callback when a socket connection is closed
    // Args: socket_id (u32)
    pub on_socket_closed: unsafe extern "C" fn(u32),

    // Callback for the Inject DLL to free strings returned by the engine
    // Args: string_ptr (*mut i8)
    pub free_string: unsafe extern "C" fn(*mut i8),

    // Callback for the Inject DLL to get the network name for a socket
    // Args: socket_id (u32)
    // Returns: *mut i8 (new UTF-8 string, must be freed via free_string) or NULL if not found
    pub get_network_name: unsafe extern "C" fn(u32) -> *mut i8,
}

// Rust wrapper for safe handling of engine callbacks and data
#[derive(Clone)]
pub struct SafeEngine {
    pub version: u32,
    pub engine_name: String,
    pub is_postprocessor: bool,

    // Store function pointers directly
    on_outgoing_irc_line_ptr: unsafe extern "C" fn(u32, *const i8, usize) -> *mut i8,
    on_incoming_irc_line_ptr: unsafe extern "C" fn(u32, *const i8, usize) -> *mut i8,
    on_socket_closed_ptr: unsafe extern "C" fn(u32),
    free_string_ptr: unsafe extern "C" fn(*mut i8),
    get_network_name_ptr: unsafe extern "C" fn(u32) -> *mut i8,
}

// Allow sending across threads if InjectEngines is shared via Arc/Mutex/RwLock
unsafe impl Send for SafeEngine {}
unsafe impl Sync for SafeEngine {}

impl SafeEngine {
    // Unsafe because it dereferences the raw pointer
    pub unsafe fn new(engine: *const FishInjectEngine) -> Option<Self> {
        if engine.is_null() {
            return None;
        }
        let engine_ref = &*engine;

        // Check version compatibility
        if engine_ref.version != FISH_INJECT_ENGINE_VERSION {
            error!(
                "Engine version mismatch: expected {}, got {}",
                FISH_INJECT_ENGINE_VERSION, engine_ref.version
            );
            return None;
        }

        // Safely get engine name
        let name = if engine_ref.engine_name.is_null() {
            warn!("Engine registered with NULL name.");
            "<Unnamed Engine>".to_string()
        } else {
            CStr::from_ptr(engine_ref.engine_name).to_string_lossy().into_owned()
        };

        // Basic check for required function pointers
        // Note: we can't easily check *if* they point to valid functions, just that they aren't null
        //
        // TODO optional: add null checks here if engines might provide null callbacks
        // if engine_ref.on_outgoing_irc_line.is_null() || ...

        Some(SafeEngine {
            version: engine_ref.version,
            engine_name: name,
            is_postprocessor: engine_ref.is_postprocessor,
            on_outgoing_irc_line_ptr: engine_ref.on_outgoing_irc_line,
            on_incoming_irc_line_ptr: engine_ref.on_incoming_irc_line,
            on_socket_closed_ptr: engine_ref.on_socket_closed,
            free_string_ptr: engine_ref.free_string,
            get_network_name_ptr: engine_ref.get_network_name,
        })
    }

    /// Wrapper for outgoing line processing
    pub fn on_outgoing_irc_line(&self, socket: u32, line: &mut String) -> bool {
        let c_line = match CString::new(line.clone()) {
            // Clone line data for C call
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Engine '{}': failed to convert outgoing line to CString: {}",
                    self.engine_name, e
                );
                return false; // Cannot call engine
            }
        };

        let returned_ptr = unsafe {
            (self.on_outgoing_irc_line_ptr)(socket, c_line.as_ptr(), line.len())
            // Pass original length
        };

        if !returned_ptr.is_null() {
            // Engine returned a modified string
            let modified_c_str = unsafe { CStr::from_ptr(returned_ptr) };
            let modified_string = modified_c_str.to_string_lossy().into_owned();

            unsafe {
                (self.free_string_ptr)(returned_ptr); // Free the string returned by the engine
            }

            // Replace original line content
            *line = modified_string;

            true // Indicate modification
        } else {
            false // No modification
        }
    }

    /// Wrapper for incoming line processing
    pub fn on_incoming_irc_line(&self, socket: u32, line: &mut String) -> bool {
        let c_line = match CString::new(line.clone()) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    "Engine '{}': failed to convert incoming line to CString: {}",
                    self.engine_name, e
                );
                return false;
            }
        };

        let returned_ptr =
            unsafe { (self.on_incoming_irc_line_ptr)(socket, c_line.as_ptr(), line.len()) };

        if !returned_ptr.is_null() {
            let modified_c_str = unsafe { CStr::from_ptr(returned_ptr) };
            let modified_string = modified_c_str.to_string_lossy().into_owned();

            unsafe {
                (self.free_string_ptr)(returned_ptr);
            }
            *line = modified_string;
            true
        } else {
            false
        }
    }

    pub fn on_socket_closed(&self, socket: u32) {
        let result = std::panic::catch_unwind(|| {
            unsafe { (self.on_socket_closed_ptr)(socket) };
        });

        if let Err(e) = result {
            error!("Engine '{}' panicked in on_socket_closed() : {:?}", self.engine_name, e);
        }
    }

    /// Wrapper for getting network name
    pub fn get_network_name(&self, socket: u32) -> Option<String> {
        let returned_ptr = unsafe { (self.get_network_name_ptr)(socket) };

        if !returned_ptr.is_null() {
            let c_str = unsafe { CStr::from_ptr(returned_ptr) };
            let network_name = c_str.to_string_lossy().into_owned();

            unsafe {
                (self.free_string_ptr)(returned_ptr);
            }

            Some(network_name)
        } else {
            None
        }
    }
}

/// Manages the collection of registered engines
pub struct InjectEngines {
    // Use RwLock for concurrent reads, occasional writes (register/unregister)
    // Separate lists for pre-processors and post-processors
    pre_engines: RwLock<Vec<SafeEngine>>,
    post_engines: RwLock<Vec<SafeEngine>>,

    // Store pointer addresses (usize) to check for duplicates during registration/unregistration
    // This is Send + Sync safe.
    registered_ptrs: Mutex<HashMap<usize, String>>,
}

impl InjectEngines {
    pub fn new() -> Self {
        InjectEngines {
            pre_engines: RwLock::new(Vec::new()),
            post_engines: RwLock::new(Vec::new()),
            registered_ptrs: Mutex::new(HashMap::new()),
        }
    }

    /// Helper to get all engines (pre and post) in a safe way
    pub fn get_engines(&self) -> Vec<SafeEngine> {
        let pre = self.pre_engines.read();
        let post = self.post_engines.read();
        pre.iter().cloned().chain(post.iter().cloned()).collect()
    }

    /// Register an engine from the C API pointer
    pub fn register(&self, engine_ptr: *const FishInjectEngine) -> bool {
        if engine_ptr.is_null() {
            error!("Attempted to register a NULL engine pointer.");
            return false;
        }
        // Use pointer address as the key (thread-safe)
        let engine_addr = engine_ptr as usize;

        // Create the safe wrapper (unsafe block)
        let safe_engine = match unsafe { SafeEngine::new(engine_ptr) } {
            Some(se) => se,
            None => {
                error!(
                    "Failed to create SafeEngine wrapper (null, version mismatch, or bad name)."
                );
                return false;
            }
        };

        // Lock pointers map first to check for duplicates and insert
        let mut ptrs = self.registered_ptrs.lock();

        if ptrs.contains_key(&engine_addr) {
            warn!(
                "Engine '{}' (addr={}) already registered.",
                safe_engine.engine_name, engine_addr
            );
            return false; // Already registered
        }
        ptrs.insert(engine_addr, safe_engine.engine_name.clone());

        drop(ptrs); // Release lock

        // Add to the appropriate engine list based on postprocessor flag
        if safe_engine.is_postprocessor {
            let mut post = self.post_engines.write();
            info!("Registering POST-processor engine: {}", safe_engine.engine_name);
            post.push(safe_engine);
        } else {
            let mut pre = self.pre_engines.write();
            info!("Registering PRE-processor engine: {}", safe_engine.engine_name);
            pre.push(safe_engine);
        }

        true // Success
    }

    /// Unregister an engine using the C API pointer
    pub fn unregister(&self, engine_ptr: *const FishInjectEngine) -> bool {
        if engine_ptr.is_null() {
            error!("Attempted to unregister a NULL engine pointer.");
            return false;
        }
        let engine_addr = engine_ptr as usize;

        // Lock pointers map to check existence and remove
        let mut ptrs = self.registered_ptrs.lock();
        let engine_name = match ptrs.remove(&engine_addr) {
            Some(name) => name,
            None => {
                warn!(
                    "Attempted to unregister an engine pointer ({:?}) that was not registered.",
                    engine_ptr
                );
                return false; // Not found
            }
        };
        drop(ptrs); // Release lock

        info!("Unregistering engine: {}", engine_name);

        // Remove from both lists (safer than checking is_postprocessor again)
        // Note : this assumes engine names are unique identifiers *after* registration check.
        // If names are not unique, this logic would need refinement (e.g., storing more info).
        let mut removed_count = 0;

        self.pre_engines.write().retain(|e| e as *const _ as usize != engine_addr);

        self.post_engines.write().retain(|e| {
            if e.engine_name == engine_name {
                removed_count += 1;
                false // Remove
            } else {
                true /* Keep */
            }
        });

        if removed_count == 0 {
            warn!(
                "Engine '{}' removed from registered pointers map but not found in pre/post lists.",
                engine_name
            );
            // This might indicate an internal inconsistency
        } else if removed_count > 1 {
            warn!(
                "Engine '{}' removed from multiple lists or multiple times. Check for non-unique names ?",
                engine_name
            );
        }

        removed_count > 0 // Return true if removed from at least one list
    }

    /// Process an outgoing line through all registered engines
    pub fn on_outgoing_irc_line(&self, socket: u32, line: &mut String) -> bool {
        let mut modified = false;

        // Run pre-processors
        let pre = self.pre_engines.read();

        for engine in pre.iter() {
            if engine.on_outgoing_irc_line(socket, line) {
                modified = true;
            }
        }
        drop(pre); // Release read lock

        // Run post-processors
        let post = self.post_engines.read();

        for engine in post.iter() {
            if engine.on_outgoing_irc_line(socket, line) {
                modified = true;
            }
        }
        drop(post); // Release read lock

        modified
    }

    /// Notify all engines that a socket has closed
    pub fn on_socket_closed(&self, socket: u32) {
        trace!("Notifying engines about closure of socket {}", socket);

        let pre = self.pre_engines.read();

        for engine in pre.iter() {
            engine.on_socket_closed(socket);
        }

        drop(pre);

        let post = self.post_engines.read();

        for engine in post.iter() {
            engine.on_socket_closed(socket);
        }
        drop(post);
    }

    /// Get a list of registered engine names
    pub fn get_engine_list(&self) -> String {
        let mut result = String::new();
        let pre = self.pre_engines.read();

        for engine in pre.iter() {
            result.push_str(&format!("[PRE:{}]", engine.engine_name));
        }

        drop(pre);

        let post = self.post_engines.read();

        for engine in post.iter() {
            result.push_str(&format!("[POST:{}]", engine.engine_name));
        }
        drop(post);

        result
    }
}

/// C API for the engine registration
#[no_mangle]
pub extern "C" fn RegisterEngine(engine: *const FishInjectEngine) -> i32 {
    // Use the global ENGINES instance from lib.rs
    use crate::ENGINES;

    let engines_lock = ENGINES.lock().unwrap();

    if let Some(ref engines_ref) = *engines_lock {
        if engines_ref.register(engine) {
            0 // Success
        } else {
            1 // Failed (already registered, version mismatch, etc.)
        }
    } else {
        error!("RegisterEngine() called but ENGINES global is not initialized !");
        -1 // Critical error
    }
}

/// C API for unregistering the engine
#[no_mangle]
pub extern "C" fn UnregisterEngine(engine: *const FishInjectEngine) -> i32 {
    use crate::ENGINES;

    let engines_lock = ENGINES.lock().unwrap();

    if let Some(ref engines_ref) = *engines_lock {
        if engines_ref.unregister(engine) {
            0 // Success
        } else {
            1 // Failed (not found)
        }
    } else {
        error!("UnregisterEngine() called but ENGINES global is not initialized !");
        -1 // Critical error
    }
}

#[no_mangle]
pub unsafe extern "C" fn GetNetworkName(socket_id: u32) -> *mut std::ffi::c_char {
    use crate::ACTIVE_SOCKETS;
    let sockets = ACTIVE_SOCKETS.lock().unwrap();
    if let Some(socket_info) = sockets.get(&socket_id) {
        let network_name_guard = socket_info.network_name.read();
        if let Some(network_name) = &*network_name_guard {
            if let Ok(c_string) = CString::new(network_name.clone()) {
                return c_string.into_raw();
            }
        }
    }
    std::ptr::null_mut()
}
