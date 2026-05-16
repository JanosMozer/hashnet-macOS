use anyhow::{Context, Result};
use csi_ipc::{IpcRequest, IpcResponse};
use tauri::{
    Manager, PhysicalPosition, SystemTray, SystemTrayEvent,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

#[tauri::command]
async fn send_ipc_command(req: IpcRequest) -> Result<IpcResponse, String> {
    println!("Received IPC command request from JS: {:?}", req);
    let res = send_ipc_command_inner(req).await.map_err(|e| e.to_string());
    println!("IPC command result: {:?}", res);
    res
}

async fn send_ipc_command_inner(req: IpcRequest) -> Result<IpcResponse> {
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
    let system_tray = SystemTray::new();

    tauri::Builder::default()
        .setup(|app| {
            tauri::async_runtime::spawn(async move {
                // Retry until csid is ready (it may not have started yet)
                for attempt in 1..=20 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    match send_ipc_command_inner(csi_ipc::IpcRequest::GetStatus).await {
                        Ok(resp) => {
                            println!("Startup IPC connected (attempt {}): {:?}", attempt, resp);
                            break;
                        }
                        Err(e) => {
                            if attempt == 20 {
                                println!("Startup IPC failed after 20 attempts: {}", e);
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
                    // Small delay so mousedown/click handlers fire before the window hides
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
