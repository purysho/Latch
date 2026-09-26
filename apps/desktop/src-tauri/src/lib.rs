use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ControlPlaneStatus {
    version: &'static str,
    runtime: &'static str,
    telemetry: bool,
    external_listeners: bool,
}

#[tauri::command]
fn control_plane_status() -> ControlPlaneStatus {
    ControlPlaneStatus {
        version: env!("CARGO_PKG_VERSION"),
        runtime: "local",
        telemetry: false,
        external_listeners: false,
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![control_plane_status])
        .run(tauri::generate_context!())
        .expect("error while running Latch");
}
