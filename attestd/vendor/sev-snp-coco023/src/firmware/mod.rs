// SPDX-License-Identifier: Apache-2.0

//! Modules for interfacing with SEV firmware.
//! Rust-friendly API wrappers to communicate with the FFI functions.

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod host;

#[cfg(feature = "snp")]
pub mod guest;

/// Linux-specific firmware interface definitions.
#[cfg(any(feature = "sev", feature = "snp"))]
pub mod linux;
