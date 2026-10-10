// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
use lee_core_v03::program::{GuestOutput, ProgramCall, read_program_call};
use logos_maps_v03_core::{Request, apply, plan};
risc0_zkvm::guest::entry!(main);
fn main() {
    match read_program_call::<Request>() {
        ProgramCall::Plan(input, request) => plan(&input, &request)
            .expect("map plan validation failed")
            .write(),
        ProgramCall::Apply(input) => {
            GuestOutput::Apply(apply(input).expect("map state validation failed")).write();
            risc0_zkvm::guest::env::exit(0);
        }
    }
}
