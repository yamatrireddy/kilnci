// SPDX-License-Identifier: Apache-2.0
// Declares the app's commands so each needs an explicit permission in
// capabilities/ (deny by default, CLAUDE.md invariant 9).
fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&[
        "get_server_url",
        "set_server_url",
        "sign_in",
        "sign_out",
        "api_request",
    ])))
    .expect("failed to run tauri-build");
}
