// SPDX-License-Identifier: MIT OR Apache-2.0
//! Registry v0.3 authority guard building block. This is not a deployed registry
//! or a replacement for its SPEL-generated schema and register/update handlers.
//! Header decoding alone does not prove that linked segments reconstruct a valid
//! guest image. Registration must separately bind the bytecode chain; this guard
//! must not be presented as a deployer/source-verification receipt.
use crate::{Error, Guard, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use lee_core_v03::{
    account::AccountId,
    native_token::NATIVE_TOKEN_PROGRAM_ID,
    program::{
        ApplyInput, ApplyOutput, PROGRAM_LOADER_ACCOUNT_ID, Plan, PlanInput, ProgramHeader,
        ProgramId,
    },
};

/// Header control is deliberately distinguished from the identity of a human
/// author and from a historical source/deployer assertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Claim {
    ThirdParty,
    HeaderAccountAuthorized,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct HeaderGuard {
    registry: AccountId,
    program: AccountId,
    expected_image: ProgramId,
}

/// Construct the read-only loader guard for a registration. The eventual
/// registry planner must also emit its own catalog/page/entry effects in this
/// same Plan; executing only this guard does not create an entry.
pub(crate) fn validate_registration(
    input: &PlanInput,
    author_index: usize,
    program_index: usize,
    expected_image: ProgramId,
    claim: Claim,
) -> Result<()> {
    let author = input
        .accounts
        .get(author_index)
        .ok_or(Error::Invalid("registry author missing"))?;
    let program = input
        .accounts
        .get(program_index)
        .ok_or(Error::Invalid("registry program header missing"))?;
    if !author.is_authorized || author.program_account_id != input.self_account_id {
        return Err(Error::Invalid(
            "registry author must authorize its registry shard",
        ));
    }
    if program.program_account_id != PROGRAM_LOADER_ACCOUNT_ID
        || [NATIVE_TOKEN_PROGRAM_ID, PROGRAM_LOADER_ACCOUNT_ID].contains(&program.account_id)
        || [NATIVE_TOKEN_PROGRAM_ID, PROGRAM_LOADER_ACCOUNT_ID].contains(&input.self_account_id)
        || expected_image == [0; 8]
    {
        return Err(Error::Invalid(
            "registry requires a guest-header selector and nonempty reviewed image",
        ));
    }
    if claim == Claim::HeaderAccountAuthorized
        && (author.account_id != program.account_id || !program.is_authorized)
    {
        return Err(Error::Invalid(
            "registry header-authority claim requires the header account's authorization",
        ));
    }
    Ok(())
}

pub fn registration_plan(
    input: &PlanInput,
    author_index: usize,
    program_index: usize,
    expected_image: ProgramId,
    claim: Claim,
) -> Result<Plan> {
    validate_registration(input, author_index, program_index, expected_image, claim)?;
    let program = &input.accounts[program_index];
    let mut plan = Plan::new(input);
    plan.inspect(
        program,
        PROGRAM_LOADER_ACCOUNT_ID,
        &Guard::Header(HeaderGuard {
            registry: input.self_account_id,
            program: program.account_id,
            expected_image,
        }),
    );
    Ok(plan)
}

/// Run as part of the registry guest's apply dispatcher. The protocol supplies
/// pre_data from the selected loader shard, rather than trusting client metadata.
/// Always returns a read-only output, including for mutable deployed headers.
pub fn apply_header_guard(input: ApplyInput) -> Result<ApplyOutput> {
    let Guard::Header(guard) = borsh::from_slice::<Guard>(&input.effect_data)
        .map_err(|_| Error::Invalid("invalid registry header guard"))?
    else {
        return Err(Error::Invalid("expected registry header guard"));
    };
    if input.self_account_id != guard.registry
        || input.selector.account_id != guard.program
        || input.selector.program_account_id != PROGRAM_LOADER_ACCOUNT_ID
    {
        return Err(Error::Invalid("registry header guard selector changed"));
    }
    let header = ProgramHeader::from_bytes(&input.pre_data).ok_or(Error::Invalid(
        "registry target does not decode as a program header",
    ))?;
    if header.image_id != guard.expected_image {
        return Err(Error::Invalid(
            "registry target image changed or differs from the claim",
        ));
    }
    Ok(ApplyOutput::new(input, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lee_core_v03::{
        account::ShardData,
        program::{AccountMeta, validate_apply_output, validate_plan},
    };
    fn input(author: AccountId) -> PlanInput {
        let registry = AccountId::new([3; 32]);
        PlanInput {
            self_account_id: registry,
            caller_account_id: None,
            accounts: vec![
                AccountMeta::new(author, true, registry),
                AccountMeta::new(
                    AccountId::new([4; 32]),
                    author == AccountId::new([4; 32]),
                    PROGRAM_LOADER_ACCOUNT_ID,
                ),
            ],
            instruction_data: vec![],
        }
    }
    fn scheduled(input: &PlanInput, claim: Claim, header: Vec<u8>) -> ApplyInput {
        let plan = registration_plan(input, 0, 1, [7; 8], claim).unwrap();
        validate_plan(input, plan.output()).unwrap();
        let effect = &plan.output().effects[0];
        ApplyInput {
            self_account_id: input.self_account_id,
            selector: effect.selector,
            pre_data: ShardData::try_from(header).unwrap(),
            effect_data: effect.data.clone(),
        }
    }
    fn header(immutable: bool) -> Vec<u8> {
        ProgramHeader {
            image_id: [7; 8],
            program_first_segment: AccountId::new([8; 32]),
            immutable,
        }
        .to_bytes()
    }
    #[test]
    fn header_authority_requires_the_actual_header_account_while_third_party_still_signs() {
        let other = input(AccountId::new([5; 32]));
        assert!(registration_plan(&other, 0, 1, [7; 8], Claim::HeaderAccountAuthorized).is_err());
        assert!(registration_plan(&other, 0, 1, [7; 8], Claim::ThirdParty).is_ok());
        let mut owner = input(AccountId::new([4; 32]));
        assert!(registration_plan(&owner, 0, 1, [7; 8], Claim::HeaderAccountAuthorized).is_ok());
        owner.accounts[0].is_authorized = false;
        for claim in [Claim::ThirdParty, Claim::HeaderAccountAuthorized] {
            assert!(registration_plan(&owner, 0, 1, [7; 8], claim).is_err());
        }
    }
    #[test]
    fn foreign_header_guard_is_read_only_and_rejects_missing_changed_or_substituted_state() {
        let input = input(AccountId::new([4; 32]));
        for immutable in [false, true] {
            let call = scheduled(&input, Claim::HeaderAccountAuthorized, header(immutable));
            let output = apply_header_guard(call.clone()).unwrap();
            assert!(output.post_data.is_none());
            validate_apply_output(&call, &output).unwrap();
            let mut illegal = output;
            illegal.post_data = Some(ShardData::empty());
            assert!(validate_apply_output(&call, &illegal).is_err());
        }
        for bytes in [vec![], vec![0; 65], {
            let mut h = header(false);
            h[0] ^= 1;
            h
        }] {
            assert!(apply_header_guard(scheduled(&input, Claim::ThirdParty, bytes)).is_err());
        }
        let mut call = scheduled(&input, Claim::ThirdParty, header(false));
        call.selector.account_id = AccountId::new([9; 32]);
        assert!(apply_header_guard(call).is_err());
        let mut call = scheduled(&input, Claim::ThirdParty, header(false));
        call.self_account_id = AccountId::new([9; 32]);
        assert!(apply_header_guard(call).is_err());
    }
    #[test]
    fn malformed_selectors_indices_images_and_reserved_programs_fail_before_planning() {
        let mut context = input(AccountId::new([4; 32]));
        assert!(registration_plan(&context, 99, 1, [7; 8], Claim::ThirdParty).is_err());
        assert!(registration_plan(&context, 0, 99, [7; 8], Claim::ThirdParty).is_err());
        assert!(registration_plan(&context, 0, 1, [0; 8], Claim::ThirdParty).is_err());
        context.accounts[1].program_account_id = context.self_account_id;
        assert!(registration_plan(&context, 0, 1, [7; 8], Claim::ThirdParty).is_err());
        context.accounts[1].program_account_id = PROGRAM_LOADER_ACCOUNT_ID;
        context.accounts[1].account_id = PROGRAM_LOADER_ACCOUNT_ID;
        assert!(registration_plan(&context, 0, 1, [7; 8], Claim::ThirdParty).is_err());
    }

    #[test]
    fn segment_header_encoding_overlap_is_not_mistaken_for_deployment_attestation() {
        // This is a format counterexample, not a deployed program. No loader
        // transaction, guest proof or executable image is established by it.
        let bytes = lee_core_v03::program::ProgramSegment {
            bytecode: vec![8; 60],
            next_segment: None,
        }
        .to_bytes();
        let header = ProgramHeader::from_bytes(&bytes).unwrap();
        assert_eq!(header.image_id[0], 60);
        let context = input(AccountId::new([4; 32]));
        let plan = registration_plan(
            &context,
            0,
            1,
            header.image_id,
            Claim::HeaderAccountAuthorized,
        )
        .unwrap();
        let effect = &plan.output().effects[0];
        let call = ApplyInput {
            self_account_id: context.self_account_id,
            selector: effect.selector,
            pre_data: bytes.try_into().unwrap(),
            effect_data: effect.data.clone(),
        };
        assert!(apply_header_guard(call).is_ok());
        // Registration must additionally validate the linked bytecode and image;
        // the narrow authorization guard intentionally does not claim to do so.
    }
}
