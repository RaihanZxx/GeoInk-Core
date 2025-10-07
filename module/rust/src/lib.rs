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
use jni::strings::JNIStr;
pub use module::ZygiskModule;

use std::ffi::{c_void, CStr, CString};
use libc::{c_char, c_int, stat};
use jni::sys::jobject;
use jni::objects::JObject;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

#[allow(dead_code)]
struct MyModule {}

static MODULE: MyModule = MyModule {};
crate::zygisk_module!(&MODULE);

static ORIG_STAT: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static ORIG_ACCESS: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static ORIG_SYSPROP_GET: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static ORIG_START_ACTIVITY: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static ORIG_APP_ON_CREATE: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

const TARGET_PACKAGE: &str = "com.rem01gaming.disclosure";
const DENYLIST_PACKAGES: &[&str] = &["com.sukisu.ultra", "com.rifsxd.ksunext"];
static IS_TARGET_APP: AtomicBool = AtomicBool::new(false);
static PLT_HOOKS_APPLIED: AtomicBool = AtomicBool::new(false);

// Define the class name as a static constant for a safe lifetime.
const CLASS_ACTIVITY: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"android/app/Activity\0") };
const CLASS_APPLICATION: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"android/app/Application\0") };


impl ZygiskModule for MyModule {
    fn on_load(&self, api: ZygiskApi, env: &mut JNIEnv) {
        #[cfg(target_os = "android")]
        {
            android_logger::init_once(
                Config::default().with_min_level(Level::Info).with_tag("zygisk_geoink_core")
            );
        }
        
        unsafe { self.register_jni_hooks(api, env); }
        info!("GeoInk-Core loaded - Ready to bypass detections");
    }

    fn pre_app_specialize(&self, _api: ZygiskApi, args: &mut AppSpecializeArgs, env: &mut JNIEnv) {
        if let Ok(process_name) = env.get_string(*args.nice_name) {
            let process_name: String = process_name.into();
            
            if process_name.starts_with(TARGET_PACKAGE) {
                info!("GeoInk-Core activated for target process: {}", process_name);
                IS_TARGET_APP.store(true, Ordering::Relaxed);
            }
        }
    }
}

impl MyModule {
    unsafe fn register_jni_hooks(&self, api: ZygiskApi, env: &mut JNIEnv) {
        // Use static constants for class names
        
        // Hook For startActivity
        info!("Registering JNI hook for Activity.startActivity...");
        // Transmute static CStr to static JNIStr. This is safe because JNIStr is repr(transparent)
        let class_name_activity: &JNIStr = std::mem::transmute(CLASS_ACTIVITY);
        let mut methods_activity = [
            jni::sys::JNINativeMethod {
                name: CString::new("startActivity").unwrap().into_raw(),
                signature: CString::new("(Landroid/content/Intent;)V").unwrap().into_raw(),
                fnPtr: hook_start_activity as *mut c_void,
            },
        ];
        api.hook_jni_native_methods(*env, class_name_activity, &mut methods_activity);
        let orig_ptr_activity = methods_activity[0].fnPtr;
        if !orig_ptr_activity.is_null() {
            ORIG_START_ACTIVITY.store(orig_ptr_activity as *mut (), Ordering::Relaxed);
        } else { error!("Failed to hook Activity.startActivity"); }
        let _ = CString::from_raw(methods_activity[0].name);
        let _ = CString::from_raw(methods_activity[0].signature);

        // Hook For Application.onCreate
        info!("Registering JNI hook for Application.onCreate...");
        let class_name_app: &JNIStr = std::mem::transmute(CLASS_APPLICATION);
        let mut methods_app = [
            jni::sys::JNINativeMethod {
                name: CString::new("onCreate").unwrap().into_raw(),
                signature: CString::new("()V").unwrap().into_raw(),
                fnPtr: hook_application_on_create as *mut c_void,
            },
        ];
        api.hook_jni_native_methods(*env, class_name_app, &mut methods_app);
        let orig_ptr_app = methods_app[0].fnPtr;
        if !orig_ptr_app.is_null() {
            ORIG_APP_ON_CREATE.store(orig_ptr_app as *mut (), Ordering::Relaxed);
        } else { error!("Failed to hook Application.onCreate"); }
        let _ = CString::from_raw(methods_app[0].name);
        let _ = CString::from_raw(methods_app[0].signature);
    }

    unsafe fn apply_plt_hooks(&self, api: ZygiskApi) {
        info!("Applying PLT hooks at stable stage...");
        let mut orig_stat_ptr: *mut () = std::ptr::null_mut();
        api.plt_hook_register(
            CStr::from_bytes_with_nul(b"libc.so\0").unwrap(), CStr::from_bytes_with_nul(b"stat\0").unwrap(),
            hook_stat as *mut c_void as *mut (), Some(&mut orig_stat_ptr),
        );
        if !orig_stat_ptr.is_null() { ORIG_STAT.store(orig_stat_ptr, Ordering::Relaxed); }
        let mut orig_access_ptr: *mut () = std::ptr::null_mut();
        api.plt_hook_register(
            CStr::from_bytes_with_nul(b"libc.so\0").unwrap(), CStr::from_bytes_with_nul(b"access\0").unwrap(),
            hook_access as *mut c_void as *mut (), Some(&mut orig_access_ptr),
        );
        if !orig_access_ptr.is_null() { ORIG_ACCESS.store(orig_access_ptr, Ordering::Relaxed); }
        let mut orig_sysprop_ptr: *mut () = std::ptr::null_mut();
        api.plt_hook_register(
            CStr::from_bytes_with_nul(b"libc.so\0").unwrap(), CStr::from_bytes_with_nul(b"__system_property_get\0").unwrap(),
            hook_sysprop_get as *mut c_void as *mut (), Some(&mut orig_sysprop_ptr),
        );
        if !orig_sysprop_ptr.is_null() { ORIG_SYSPROP_GET.store(orig_sysprop_ptr, Ordering::Relaxed); }
        if !api.plt_hook_commit() {
            error!("Failed to commit PLT hooks.");
        } else {
            info!("PLT hooks committed successfully.");
        }
    }
}
#[no_mangle]
extern "C" fn hook_application_on_create(env: *mut jni::sys::JNIEnv, app: jobject) {
    let is_target = IS_TARGET_APP.load(Ordering::Relaxed);
    if is_target {
        if PLT_HOOKS_APPLIED.compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            let api_table = unsafe { &*(env as *const *const i32).offset(-2) as *const _ as *const crate::binding::RawApiTable };
            let api = ZygiskApi::from_raw(unsafe { &*api_table });
            unsafe { MODULE.apply_plt_hooks(api) };
        }
    }
    let orig_ptr = ORIG_APP_ON_CREATE.load(Ordering::Relaxed);
    if !orig_ptr.is_null() {
        let orig_fn = unsafe {
            std::mem::transmute::<*mut (), extern "C" fn(*mut jni::sys::JNIEnv, jobject)>(orig_ptr)
        };
        orig_fn(env, app);
    }
}
extern "C" fn hook_stat(pathname: *const c_char, statbuf: *mut stat) -> c_int {
    let orig_ptr = ORIG_STAT.load(Ordering::Relaxed);
    if orig_ptr.is_null() { return 0; }
    let orig_fn = unsafe { std::mem::transmute::<*mut (), extern "C" fn(*const c_char, *mut stat) -> c_int>(orig_ptr) };
    if IS_TARGET_APP.load(Ordering::Relaxed) {
        if !pathname.is_null() {
            let path_str = unsafe { CStr::from_ptr(pathname) }.to_str().unwrap_or_default();
            if path_str.starts_with("/system/addon.d") || path_str.starts_with("/sdcard/Fox") {
                info!("Hiding file/dir (stat): {}", path_str);
                return -1;
            }
        }
    }
    orig_fn(pathname, statbuf)
}
extern "C" fn hook_access(pathname: *const c_char, mode: c_int) -> c_int {
    let orig_ptr = ORIG_ACCESS.load(Ordering::Relaxed);
    if orig_ptr.is_null() { return 0; }
    let orig_fn = unsafe { std::mem::transmute::<*mut (), extern "C" fn(*const c_char, c_int) -> c_int>(orig_ptr) };
    if IS_TARGET_APP.load(Ordering::Relaxed) {
        if !pathname.is_null() {
            let path_str = unsafe { CStr::from_ptr(pathname) }.to_str().unwrap_or_default();
            if path_str.starts_with("/system/addon.d") || path_str.starts_with("/sdcard/Fox") {
                info!("Hiding file/dir (access): {}", path_str);
                return -1;
            }
        }
    }
    orig_fn(pathname, mode)
}
extern "C" fn hook_sysprop_get(name: *const c_char, value: *mut c_char) -> c_int {
    let orig_ptr = ORIG_SYSPROP_GET.load(Ordering::Relaxed);
    if orig_ptr.is_null() { return 0; }
    let orig_fn = unsafe { std::mem::transmute::<*mut (), extern "C" fn(*const c_char, *mut c_char) -> c_int>(orig_ptr) };
    if IS_TARGET_APP.load(Ordering::Relaxed) {
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
    }
    orig_fn(name, value)
}
#[no_mangle]
extern "C" fn hook_start_activity(env: *mut jni::sys::JNIEnv, activity: jobject, intent: jobject) {
    let orig_ptr = ORIG_START_ACTIVITY.load(Ordering::Relaxed);
    let orig_fn = if !orig_ptr.is_null() {
        Some(unsafe { std::mem::transmute::<*mut (), extern "C" fn(*mut jni::sys::JNIEnv, jobject, jobject)>(orig_ptr) })
    } else { None };
    if !IS_TARGET_APP.load(Ordering::Relaxed) || orig_fn.is_none() {
        if let Some(f) = orig_fn { f(env, activity, intent); }
        return;
    }
    let jni_env = match unsafe { JNIEnv::from_raw(env) } {
        Ok(env) => env,
        Err(_) => { if let Some(f) = orig_fn { f(env, activity, intent); } return; }
    };
    if intent.is_null() {
        if let Some(f) = orig_fn { f(env, activity, intent); }
        return;
    }
    let intent_obj = JObject::from(intent);
    if let Ok(component_result) = jni_env.call_method(intent_obj, "getComponent", "()Landroid/content/ComponentName;", &[]) {
        if let Ok(component_obj) = component_result.l() {
            if !component_obj.is_null() {
                if let Ok(pkg_name_result) = jni_env.call_method(component_obj, "getPackageName", "()Ljava/lang/String;", &[]) {
                    if let Ok(pkg_name_java) = pkg_name_result.l() {
                        if let Ok(pkg_name_rust) = jni_env.get_string(pkg_name_java.into()) {
                            let pkg_name_str: String = pkg_name_rust.into();
                            if DENYLIST_PACKAGES.contains(&pkg_name_str.as_str()) {
                                info!("GeoInk-Core: Blocked startActivity to {}", pkg_name_str);
                                let _ = jni_env.throw_new("android/content/ActivityNotFoundException", "Blocked by GeoInk-Core");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(f) = orig_fn { f(env, activity, intent); }
}
