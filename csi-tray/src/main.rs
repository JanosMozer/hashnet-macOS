use anyhow::{Context, Result};
use csi_ipc::{IpcRequest, IpcResponse};
use tauri::{
    Manager, PhysicalPosition, SystemTray, SystemTrayEvent,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[tauri::command]
async fn send_ipc_command(req: IpcRequest) -> Result<IpcResponse, String> {
    // Tauri IPC command handler exposed to the HTML frontend.
    let res = send_ipc_command_inner(req).await.map_err(|e| e.to_string());
    res
}

async fn send_ipc_command_inner(req: IpcRequest) -> Result<IpcResponse> {
    // Sends a JSON-serialized IPC request to the csid Unix Domain Socket and reads the response.
    let mut stream = UnixStream::connect("/tmp/csi.sock")
        .await
        .context("Failed to connect to csid daemon")?;

    let mut req_json = serde_json::to_string(&req)?;
    req_json.push('\n');

    stream.write_all(req_json.as_bytes()).await?;

    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;

    let resp_str = std::str::from_utf8(&buf[..n])?.trim();
    let resp: IpcResponse = serde_json::from_str(resp_str)?;

    Ok(resp)
}

fn main() {
    // Entry point for the Tauri system tray frontend application.
    let system_tray = SystemTray::new();

    tauri::Builder::default()
        .setup(|_app| {
            tauri::async_runtime::spawn(async move {
                // If csid is not reachable, spawn it from the same directory as this binary
                if UnixStream::connect("/tmp/csi.sock").await.is_err() {
                    if let Ok(exe_path) = std::env::current_exe() {
                        if let Some(bin_dir) = exe_path.parent() {
                            let csid_path = bin_dir.join("csid");
                            if csid_path.exists() {
                                let _ = std::process::Command::new(csid_path).spawn();
                            }
                        }
                    }
                }

                for attempt in 1..=20 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    match send_ipc_command_inner(csi_ipc::IpcRequest::GetStatus).await {
                        Ok(resp) => {
                            eprintln!("Startup IPC connected (attempt {}): {:?}", attempt, resp);
                            break;
                        }
                        Err(e) => {
                            if attempt == 20 {
                                eprintln!("Startup IPC failed after 20 attempts: {}", e);
                            }
                        }
                    }
                }
            });
            Ok(())
        })
        .system_tray(system_tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick { position, size, .. } => {
                if let Some(window) = app.get_window("main") {
                    if window.is_visible().unwrap_or(false) {
                        window.hide().unwrap();
                    } else {
                        if let Ok(window_size) = window.outer_size() {
                            let x = position.x as i32 - (window_size.width as i32 / 2);
                            let y = position.y as i32 + size.height as i32;
                            let _ = window.set_position(tauri::Position::Physical(PhysicalPosition { x, y }));
                        }
                        window.show().unwrap();
                        window.set_focus().unwrap();
                    }
                }
            }
            _ => {}
        })
        .on_window_event(|event| match event.event() {
            tauri::WindowEvent::Focused(is_focused) => {
                if !is_focused {
                    let window = event.window().clone();
                    tauri::async_runtime::spawn(async move {
                        tokio::time::sleep(tokio::time::Duration::from_millis(150)).await;
                        let _ = window.hide();
                    });
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![send_ipc_command])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
