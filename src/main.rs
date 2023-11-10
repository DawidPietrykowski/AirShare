// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpListener;
use std::path::Path;
use std::thread;

use std::env;

#[cfg(feature = "tauri-app")]
use auto_launch::AutoLaunchBuilder;
#[cfg(feature = "tauri-app")]
use notify_rust::Notification;
#[cfg(feature = "tauri-app")]
use std::env::current_exe;
#[cfg(feature = "tauri-app")]
use std::path::PathBuf;
#[cfg(feature = "tauri-app")]
use std::sync::{mpsc, Arc};
#[cfg(feature = "tauri-app")]
use tauri::{
    AppHandle, CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, WindowBuilder,
};

mod nearby_share;
mod mdns;

fn get_device_name() -> String {
    env::var("DEVICE_NAME")
        .unwrap_or(whoami::devicename())
        .to_string()
}

fn get_server_port() -> u16 {
    env::var("SERVER_PORT")
    .unwrap_or("5200".to_string())
    .parse::<u16>()
    .unwrap()
}

#[cfg(feature = "tauri-app")]
fn show_popup(device_name: &str, filename: &str, cl: &AppHandle) -> bool {
    let file_extension = Path::new(filename)
        .extension()
        .unwrap_or_default()
        .to_str()
        .unwrap_or("");
    let mut file_base_name: String = match Path::new(filename).file_name() {
        Some(name) => name.to_str().unwrap_or("unknown").to_string(),
        None => "unknown".to_string(),
    };
    if file_base_name.len() > 10 {
        file_base_name.truncate(10);
    }

    let filename = format!("{}(...).{}", file_base_name, file_extension);

    let win = &WindowBuilder::new(
        cl,
        "popup".to_string(),
        tauri::WindowUrl::App(Path::new("index.html").to_path_buf()),
    )
    .inner_size(300.0, 165.0)
    .resizable(false)
    .always_on_top(true)
    .center()
    .title("AirShare")
    .initialization_script(
        &format!(
            r#"
            function applyText(){{ 
            document.getElementById('smalltext').textContent = "{} wants to send you file {}";
            }}
            "#,
            device_name, filename
        )
        .to_string(),
    )
    .build()
    .unwrap();

    let (sender, receiver) = mpsc::channel::<bool>();
    let handler = win.listen("confirmation-event", move |payload| {
        let accepted = payload.payload().unwrap_or("decline").contains("accept");
        sender.send(accepted).unwrap();
    });
    let res = receiver.recv().unwrap();
    win.unlisten(handler);
    let _ = win.close();
    res
}


#[cfg(feature = "tauri-app")]
fn run_nearby_server(window: Arc<AppHandle>) {
    let port = get_server_port();
    let device_name = get_device_name();

    thread::spawn(move || {
        mdns::run_mdns_server(device_name.clone(), port);
    });

    let download_path = get_download_path();
    println!("Download path: {}", download_path.to_str().unwrap_or(""));

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).unwrap();
    listener.take_error().unwrap();

    for stream in listener.incoming() {
        let mut str = stream.unwrap();
        println!("New connection from address: {}", str.peer_addr().unwrap());
        let path = download_path.clone();
        let cl = window.clone();
        thread::spawn(move || {
            let res = nearby_share::handle_client_init(&mut str, path, |filename, device_name| {
                show_popup(device_name, filename, cl.as_ref())
            });
            if let Some(fname) = res {
                finish_notification(fname.as_str());
            }
        });
    }
}

#[cfg(feature = "tauri-app")]
fn get_download_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        home::home_dir()
            .unwrap_or(Path::new("~/Downloads").to_path_buf())
            .join(Path::new("Downloads"))
    }
    #[cfg(target_os = "macos")]
    {
        home::home_dir()
            .unwrap_or(Path::new("~/Downloads").to_path_buf())
            .join(Path::new("Downloads"))
    }
    #[cfg(target_os = "windows")]
    {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let hklm = RegKey::predef(HKEY_CURRENT_USER);
        Path::new(
            &hklm
                .open_subkey(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
                )
                .unwrap()
                .get_value::<String, String>(r"{374DE290-123F-4565-9164-39C4925E467B}".to_string())
                .unwrap_or("C:\\Downloads".to_string()),
        )
        .to_path_buf()
    }
}

#[cfg(feature = "tauri-app")]
fn finish_notification(filename: &str) {
    Notification::new()
        .summary("File received")
        .body(format!("Received {}", filename).as_str())
        .timeout(4000)
        .show()
        .unwrap();
}

#[cfg(feature = "docker")]
fn run_docker_nearby_server() {
    // Create a service info.
    let device_name = get_device_name();
    let port = get_server_port();

    println!("Device name: {}", device_name);

    thread::spawn(move || {
        mdns::run_mdns_server(device_name.clone(), port);
    });

    let download_path =
        Path::new::<String>(&env::var("DOWNLOAD_PATH").unwrap_or("/downloads".to_string()))
            .to_path_buf();
    println!("Download path: {:?}", download_path);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).unwrap();
    listener.take_error().unwrap();

    for stream in listener.incoming() {
        let mut str = stream.unwrap();
        println!("New connection from address: {}", str.peer_addr().unwrap());
        let path = download_path.clone();
        thread::spawn(move || {
            let _ = nearby_share::handle_client_init(&mut str, path, |_, _| true);
        });
    }
}

fn main() {
    #[cfg(feature = "tauri-app")]
    {
        env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        let info = CustomMenuItem::new("AirShare".to_string(), "AirShare").disabled();
        let quit = CustomMenuItem::new("quit".to_string(), "Quit");
        let tray_menu = SystemTrayMenu::new().add_item(info).add_item(quit);
        let system_tray = SystemTray::new().with_menu(tray_menu);

        let context = tauri::generate_context!();
        let app = tauri::Builder::default()
            .system_tray(system_tray)
            .on_system_tray_event(|_app, event| match event {
                SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                    "quit" => {
                        std::process::exit(0);
                    }
                    _ => {}
                },
                _ => {}
            })
            .setup(|app| {
                #[cfg(target_os = "macos")]
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);

                let app_name = &app.package_info().name;
                let current_exe = current_exe().unwrap();

                let auto_start = AutoLaunchBuilder::new()
                    .set_app_name(&app_name)
                    .set_app_path(&current_exe.to_str().unwrap())
                    .set_use_launch_agent(true)
                    .build()
                    .unwrap();

                auto_start.enable().unwrap();

                Ok(())
            })
            .build(context)
            .expect("error while running tauri application");

        let cl = Arc::new(app.app_handle());
        thread::spawn(move || {
            run_nearby_server(cl);
        });

        app.run(|_app_handle, event| match event {
            tauri::RunEvent::ExitRequested { api, .. } => {
                api.prevent_exit();
            }
            _ => {}
        });
    }
    #[cfg(feature = "docker")]
    run_docker_nearby_server();
    #[cfg(not(any(feature = "tauri-app", feature = "docker")))]
    println!("Unless testing development enable one of the features: tauri-app, docker");
    #[cfg(not(any(feature = "tauri-app", feature = "docker")))]
    {
        // Get port and device name
        let port = get_server_port();
        let device_name = get_device_name();

        // Start tcp server
        let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).unwrap();
        listener.take_error().unwrap();

        // Start mdns
        thread::spawn(move || {
            mdns::run_mdns_server(device_name.clone(), port);
        });

        // Run server
        for stream in listener.incoming() {
            let mut str = stream.unwrap();
            println!("New connection from address: {}", str.peer_addr().unwrap());
            let path = Path::new("tmp").to_path_buf();
            thread::spawn(move || {
                let _ = nearby_share::handle_client_init(&mut str, path, |_, _| true);
            });
        }
    }
}
