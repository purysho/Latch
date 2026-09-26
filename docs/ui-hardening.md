# Desktop UI hardening

Phase 10 turns the initial visual prototype into a safer public-preview surface without pretending that sample data is live enforcement.

## Changes

- All representative sessions, approvals and audit rows are explicitly labelled as preview/demo data.
- Private project names were removed from the public UI.
- Navigation now renders view-specific content instead of changing only the page heading.
- Preview approval buttons are labelled as simulations and cannot be mistaken for real authorization.
- The Tauri backend exposes a narrow read-only `control_plane_status` command.
- Runtime status reports local execution, telemetry state and listener state without claiming live enforcement wiring.
- Keyboard focus styles and reduced-motion handling were added.
- Tauri now ships with a restrictive content-security policy instead of `csp: null`.
- No `dangerouslySetInnerHTML`, remote script source or remote image source is used.

## V0.1 UI boundary

The Rust crates are the enforcement surface. The desktop UI is a hardened local preview of the control plane and does not yet claim to be a live operator console for every adapter. This boundary is visible in the product rather than hidden in release notes.
