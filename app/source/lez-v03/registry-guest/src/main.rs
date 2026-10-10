// SPDX-License-Identifier: MIT OR Apache-2.0
//! Executable guard-stage harness. It does not implement registry storage or its final SPEL ABI.
#![no_main]
use lee_core_v03::program::{GuestOutput, ProgramCall, read_program_call};
use logos_registry_v03_core::{GuardRequest, apply_guard, bytecode_registration_plan};
risc0_zkvm::guest::entry!(main);
fn main() {
    match read_program_call::<GuardRequest>() {
        ProgramCall::Plan(input, request) => bytecode_registration_plan(
            &input,
            usize::from(request.author_index),
            usize::from(request.program_index),
            request.expected_image,
            request.claim,
            &request.witness,
        )
        .expect("registry bytecode/authority guard failed")
        .write(),
        ProgramCall::Apply(input) => {
            let output = apply_guard(input).expect("registry state guard failed");
            GuestOutput::Apply(output).write();
            risc0_zkvm::guest::env::exit(0);
        }
    }
}
