mod api;
mod binding;
#[doc(hidden)]
pub mod macros;
mod module;

#[macro_use]
extern crate log;
#[cfg(target_os = "android")]
extern crate android_logger;

#[cfg(target_os = "android")]
use {android_logger::Config, log::Level};

pub use api::ZygiskApi;
pub use binding::{AppSpecializeArgs, ServerSpecializeArgs, StateFlags, ZygiskOption, API_VERSION};
use jni::JNIEnv;
pub use module::ZygiskModule;

use std::ffi::{c_void, CStr, CString};
use libc::{c_char, c_int, stat};
use jni::sys::jobject;
use jni::objects::{JObject, JString as JNIString};
use std::sync::atomic::{AtomicPtr, Ordering};

#[allow(dead_code)]
struct MyModule {}

static MODULE: MyModule = MyModule {};
crate::zygisk_module!(&MODULE);

static ORIG_STAT: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static ORIG_ACCESS: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static ORIG_SYSPROP_GET: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static ORIG_START_ACTIVITY: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

const TARGET_PACKAGE: &str = "com.rem01gaming.disclosure";
const DENYLIST_PACKAGES: &[&str] = &["com.sukisu.ultra", "com.rifsxd.ksunext"];

impl ZygiskModule for MyModule {
    fn on_load(&self, _api: ZygiskApi, _env: &mut JNIEnv) {
        #[cfg(target_os = "android")]
        {
            android_logger::init_once(
                Config::default().with_min_level(Level::Info).with_tag("zygisk_geoink_core")
            );
        }
        info!("GeoInk-Core loaded - Ready for action!");
        // CLEAR on_load. We don't do any hooks in Zygote.
    }

    fn pre_app_specialize(&self, api: ZygiskApi, args: &mut AppSpecializeArgs, env: &mut JNIEnv) {
        // Check the process name directly here
        let process_name_opt: Option<String> = if let Ok(process_name_jstr) = env.get_string(*args.nice_name) {
            Some(process_name_jstr.into())
        } else {
            None
        };
        
        if let Some(process_name) = process_name_opt {
            // If this is the target process (either UI or Service)...
            if process_name.starts_with(TARGET_PACKAGE) {
                info!("GeoInk-Core activated for target process: {}", process_name);
                
                // ...DIRECTLY apply all the hooks here!
                // This is the most reliable place.
                unsafe { self.apply_all_hooks(&api, env); }
            }
        }
    }
}

impl MyModule {
    // One function to implement all hooks
    unsafe fn apply_all_hooks(&self, api: &ZygiskApi, env: &mut JNIEnv) {
        self.apply_jni_hooks(api, env);
        self.apply_plt_hooks(api);
    }

    unsafe fn apply_jni_hooks(&self, api: &ZygiskApi, env: &mut JNIEnv) {
        info!("Applying JNI hooks...");
        
        // CHANGE TARGET to `android.app.ContextImpl` - this is more fundamental
        let class_name = "android/app/ContextImpl";
        let method_name = "startActivity";
        // Signature is a little different, we need `Bundle`
        let method_sig = "(Landroid/content/Intent;Landroid/os/Bundle;)V";

        let class_name_cstr = CString::new(class_name).unwrap();
        let mut methods = [
            jni::sys::JNINativeMethod {
                name: CString::new(method_name).unwrap().into_raw(),
                signature: CString::new(method_sig).unwrap().into_raw(),
                fnPtr: hook_start_activity as *mut c_void,
            },
        ];

        api.hook_jni_native_methods(*env, &class_name_cstr, &mut methods);

        let orig_ptr = methods[0].fnPtr;
        if !orig_ptr.is_null() {
            ORIG_START_ACTIVITY.store(orig_ptr as *mut (), Ordering::Relaxed);
            info!("Successfully hooked ContextImpl.startActivity");
        } else {
            error!("Failed to hook ContextImpl.startActivity");
        }
        
        // Clearing memory allocated by CString::into_raw
        let _ = CString::from_raw(methods[0].name);
        let _ = CString::from_raw(methods[0].signature);
    }
    
    unsafe fn apply_plt_hooks(&self, api: &ZygiskApi) {
        info!("Applying PLT hooks...");

        // Hook stat
        let mut orig_stat_ptr: *mut () = std::ptr::null_mut();
        api.plt_hook_register(
            CStr::from_bytes_with_nul(b"libc.so\0").unwrap(), CStr::from_bytes_with_nul(b"stat\0").unwrap(),
            hook_stat as *mut (), Some(&mut orig_stat_ptr),
        );
        if !orig_stat_ptr.is_null() { ORIG_STAT.store(orig_stat_ptr, Ordering::Relaxed); }

        // Hook access
        let mut orig_access_ptr: *mut () = std::ptr::null_mut();
        api.plt_hook_register(
            CStr::from_bytes_with_nul(b"libc.so\0").unwrap(), CStr::from_bytes_with_nul(b"access\0").unwrap(),
            hook_access as *mut (), Some(&mut orig_access_ptr),
        );
        if !orig_access_ptr.is_null() { ORIG_ACCESS.store(orig_access_ptr, Ordering::Relaxed); }

        // Hook __system_property_get
        let mut orig_sysprop_ptr: *mut () = std::ptr::null_mut();
        api.plt_hook_register(
            CStr::from_bytes_with_nul(b"libc.so\0").unwrap(), CStr::from_bytes_with_nul(b"__system_property_get\0").unwrap(),
            hook_sysprop_get as *mut (), Some(&mut orig_sysprop_ptr),
        );
        if !orig_sysprop_ptr.is_null() { ORIG_SYSPROP_GET.store(orig_sysprop_ptr, Ordering::Relaxed); }

        // Commit all PLT hooks at once
        if !api.plt_hook_commit() {
            error!("Failed to commit PLT hooks.");
        } else {
            info!("PLT hooks committed successfully.");
        }
    }
}

extern "C" fn hook_stat(pathname: *const c_char, statbuf: *mut stat) -> c_int {
    let orig_ptr = ORIG_STAT.load(Ordering::Relaxed);
    if orig_ptr.is_null() { return -1; } // Return error if original pointer does not exist
    let orig_fn = unsafe { std::mem::transmute::<*mut (), extern "C" fn(*const c_char, *mut stat) -> c_int>(orig_ptr) };
    
    if !pathname.is_null() {
        let path_str = unsafe { CStr::from_ptr(pathname) }.to_str().unwrap_or_default();
        if path_str.starts_with("/system/addon.d") || path_str.starts_with("/sdcard/Fox") {
            info!("Hiding file/dir (stat): {}", path_str);
            return -1; // ENOENT
        }
    }
    
    orig_fn(pathname, statbuf)
}

extern "C" fn hook_access(pathname: *const c_char, mode: c_int) -> c_int {
    let orig_ptr = ORIG_ACCESS.load(Ordering::Relaxed);
    if orig_ptr.is_null() { return -1; }
    let orig_fn = unsafe { std::mem::transmute::<*mut (), extern "C" fn(*const c_char, c_int) -> c_int>(orig_ptr) };
    
    if !pathname.is_null() {
        let path_str = unsafe { CStr::from_ptr(pathname) }.to_str().unwrap_or_default();
        if path_str.starts_with("/system/addon.d") || path_str.starts_with("/sdcard/Fox") {
            info!("Hiding file/dir (access): {}", path_str);
            return -1; // ENOENT
        }
    }
    
    orig_fn(pathname, mode)
}

extern "C" fn hook_sysprop_get(name: *const c_char, value: *mut c_char) -> c_int {
    let orig_ptr = ORIG_SYSPROP_GET.load(Ordering::Relaxed);
    if orig_ptr.is_null() { return 0; }
    let orig_fn = unsafe { std::mem::transmute::<*mut (), extern "C" fn(*const c_char, *mut c_char) -> c_int>(orig_ptr) };
    
    if !name.is_null() {
        let prop_name = unsafe { CStr::from_ptr(name) }.to_str().unwrap_or_default();
        if prop_name == "ro.boot.realmebootstate" {
            info!("Faking prop: {} -> green", prop_name);
            let green_val = b"green\0";
            unsafe { std::ptr::copy_nonoverlapping(green_val.as_ptr() as *const c_char, value, green_val.len()); }
            return (green_val.len() - 1) as c_int;
        }
        if prop_name.contains("ro.lineage") {
            info!("Hiding LineageOS prop: {}", prop_name);
            return 0;
        }
    }
    
    orig_fn(name, value)
}

#[no_mangle]
extern "C" fn hook_start_activity(env: *mut jni::sys::JNIEnv, _context: jobject, intent: jobject, bundle: jobject) {
    let orig_ptr = ORIG_START_ACTIVITY.load(Ordering::Relaxed);
    let orig_fn = if !orig_ptr.is_null() {
        Some(unsafe { std::mem::transmute::<*mut (), extern "C" fn(*mut jni::sys::JNIEnv, jobject, jobject, jobject)>(orig_ptr) })
    } else { None };

    if intent.is_null() {
        if let Some(f) = orig_fn { f(env, _context, intent, bundle); }
        return;
    }

    let jni_env = unsafe { JNIEnv::from_raw(env).unwrap() };
    let intent_obj = JObject::from(intent);

    if let Ok(component_result) = jni_env.call_method(intent_obj, "getComponent", "()Landroid/content/ComponentName;", &[]) {
        if let Ok(component_obj) = component_result.l() {
            if !component_obj.is_null() {
                if let Ok(pkg_name_result) = jni_env.call_method(component_obj, "getPackageName", "()Ljava/lang/String;", &[]) {
                    if let Ok(pkg_name_java) = pkg_name_result.l() {
                        if let Ok(pkg_name_rust) = jni_env.get_string(JNIString::from(pkg_name_java)) {
                            let pkg_name_str: String = pkg_name_rust.into();
                            if DENYLIST_PACKAGES.contains(&pkg_name_str.as_str()) {
                                info!("GeoInk-Core: Blocked startActivity to {}", pkg_name_str);
                                let _ = jni_env.throw_new("android/content/ActivityNotFoundException", "Blocked by GeoInk-Core");
                                return; // Call blocked, do not forward to original function.
                            }
                        }
                    }
                }
            }
        }
    }

    // If not blocked, call the original function
if let Some(f) = orig_fn { f(env, _context, intent, bundle); }
}
