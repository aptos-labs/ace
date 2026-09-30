// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

#[derive(Copy, Clone)]
pub(crate) enum Flow {
    Unknown,
    Basic,
    Custom,
    ThresholdVrf,
    Reconstruction,
    CvmRootVrf,
}

impl Flow {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Flow::Unknown => "?",
            Flow::Basic => "basic",
            Flow::Custom => "custom",
            Flow::ThresholdVrf => "threshold_vrf",
            Flow::Reconstruction => "reconstruction",
            Flow::CvmRootVrf => "cvm_root_vrf",
        }
    }
}
