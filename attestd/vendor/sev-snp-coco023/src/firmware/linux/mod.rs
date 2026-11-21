// SPDX-License-Identifier: Apache-2.0

/// Linux host firmware ABI types.
pub mod host;

/// Linux guest firmware interface definitions.
#[cfg(feature = "snp")]
pub mod guest;

pub(crate) const _4K_PAGE: usize = 4096;
