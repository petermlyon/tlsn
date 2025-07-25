//! PRF modes.

/// Modes for the PRF.
#[derive(Debug, Clone, Copy)]
pub enum Mode {
    /// Computes some hashes locally.
    Reduced,
    /// Computes the whole PRF in MPC.
    Normal,
}
