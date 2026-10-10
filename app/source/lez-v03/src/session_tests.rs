// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::session::{Channel, OWNER_MODULE, Session};
use logos_wallet_policy::principal::Principal;
use serde_json::{Value, json};
fn module(name: &str) -> Principal {
    Principal::Module {
        name: name.into(),
        instance: String::new(),
    }
}
fn owner(session: &mut Session, value: Value) -> Value {
    session
        .dispatch(&module(OWNER_MODULE), Channel::Owner, &value.to_string())
        .unwrap()
}
#[test]
fn private_identity_management_is_owner_only_and_lock_removes_private_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v03.sqlite");
    let mut session = Session::new(&path).unwrap();
    let import = json!({"method":"import_private","label":"Private owner identity","spending_seed":hex::encode([61;32]),"identifier":hex::encode([62;32])});
    for caller in [
        module("reader"),
        Principal::Derived {
            parent: OWNER_MODULE.into(),
            leaf: "other".into(),
        },
    ] {
        assert!(
            session
                .dispatch(&caller, Channel::Owner, &import.to_string())
                .is_err()
        );
    }
    assert!(!path.exists());
    owner(
        &mut session,
        json!({"method":"create","password":"synthetic private session"}),
    );
    assert!(
        session
            .dispatch(&module(OWNER_MODULE), Channel::Dapp, &import.to_string())
            .is_err()
    );
    let imported = owner(&mut session, import);
    assert_eq!(imported["history_recovered"], false);
    let generated = owner(
        &mut session,
        json!({"method":"generate_private","label":"Generated private identity"}),
    );
    assert_ne!(imported["account"], generated["account"]);
    let snapshot = owner(&mut session, json!({"method":"state"}));
    assert_eq!(snapshot["accounts"], json!([]));
    assert_eq!(snapshot["private_accounts"].as_array().unwrap().len(), 2);
    assert_eq!(
        snapshot["private_accounts"][0]["account"],
        imported["account"]
    );
    assert_eq!(snapshot["private_accounts"][0]["initialized"], false);
    assert!(snapshot["private_accounts"][0]["native_balance"].is_null());
    assert!(!snapshot.to_string().contains(&hex::encode([61; 32])));
    assert!(!snapshot.to_string().contains(&hex::encode([62; 32])));
    for method in [
        "state",
        "private_accounts",
        "private_activity",
        "generate_private",
    ] {
        assert!(
            session
                .dispatch(
                    &module("reader"),
                    Channel::Dapp,
                    &json!({"method":method}).to_string()
                )
                .is_err()
        );
    }
    let id: crate::AccountId = imported["account"].as_str().unwrap().parse().unwrap();
    assert!(session.dispatch(&module(OWNER_MODULE),Channel::Owner,&json!({"method":"set_grant","principal":module("reader"),"grant":{"accounts":[id.bytes()],"scopes":["Accounts"]}}).to_string()).is_err());
    let locked = owner(&mut session, json!({"method":"lock"}));
    assert!(locked["private_accounts"].is_null());
    assert_eq!(locked["private_activity"], json!([]));
    assert!(!locked.to_string().contains("Private owner identity"));
    drop(session);
    let mut session = Session::new(&path).unwrap();
    let restored = owner(
        &mut session,
        json!({"method":"unlock","password":"synthetic private session"}),
    );
    assert_eq!(restored["private_accounts"], snapshot["private_accounts"]);
}
#[test]
fn identity_and_channel_checks_precede_parsing_or_wallet_creation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v03.sqlite");
    let mut session = Session::new(&path).unwrap();
    for caller in [
        module("other"),
        Principal::LocalCli,
        Principal::Derived {
            parent: OWNER_MODULE.into(),
            leaf: "view".into(),
        },
        Principal::Module {
            name: OWNER_MODULE.into(),
            instance: "another".into(),
        },
    ] {
        assert!(
            session
                .dispatch(
                    &caller,
                    Channel::Owner,
                    r#"{"method":"create","password":"secret"}"#
                )
                .is_err()
        );
        assert!(
            session
                .dispatch(&caller, Channel::Owner, "malformed")
                .is_err()
        );
    }
    for body in [
        r#"{"method":"create","password":"secret"}"#,
        r#"{"method":"accounts","caller":"prize_wallet_ui"}"#,
        r#"{"method":"lock"}"#,
    ] {
        assert!(
            session
                .dispatch(&module(OWNER_MODULE), Channel::Dapp, body)
                .is_err()
        );
    }
    let error = session
        .dispatch(
            &module(OWNER_MODULE),
            Channel::Owner,
            r#"{"method":"this-could-be-a-password"}"#,
        )
        .unwrap_err()
        .to_string();
    assert!(!error.contains("this-could-be-a-password"));
    assert!(
        session
            .dispatch(&module(OWNER_MODULE), Channel::Owner, &"x".repeat(16385))
            .is_err()
    );
    assert!(!path.exists());
    assert!(Session::new(std::path::Path::new("relative.sqlite")).is_err());
}
#[test]
fn account_access_is_scoped_and_failed_unlock_closes_the_old_session() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v03.sqlite");
    let mut session = Session::new(&path).unwrap();
    let created = owner(
        &mut session,
        json!({"method":"create","password":"synthetic-password"}),
    );
    assert_eq!(created["accounts"], json!([]));
    let generated = owner(
        &mut session,
        json!({"method":"generate_account","label":"Owner-only label"}),
    );
    let account = generated["account"].as_str().unwrap();
    let id: crate::AccountId = account.parse().unwrap();
    let app = module("reader");
    assert!(
        session
            .dispatch(&app, Channel::Dapp, r#"{"method":"accounts"}"#)
            .is_err()
    );
    owner(
        &mut session,
        json!({"method":"set_grant","principal":app,
        "grant":{"accounts":[id.bytes()],"scopes":["Accounts"]}}),
    );
    let visible = session
        .dispatch(&app, Channel::Dapp, r#"{"method":"accounts"}"#)
        .unwrap();
    assert_eq!(visible["accounts"], json!([account]));
    assert!(!visible.to_string().contains("Owner-only label"));
    assert!(
        session
            .dispatch(&module("other"), Channel::Dapp, r#"{"method":"accounts"}"#)
            .is_err()
    );
    assert_eq!(
        session
            .dispatch(&app, Channel::Dapp, r#"{"method":"activity"}"#)
            .unwrap()["transactions"],
        json!([])
    );
    let wrong = json!({"method":"unlock","password":"wrong"});
    assert!(
        session
            .dispatch(&module(OWNER_MODULE), Channel::Owner, &wrong.to_string())
            .is_err()
    );
    assert_eq!(
        owner(&mut session, json!({"method":"state"}))["unlocked"],
        false
    );
    assert!(
        session
            .dispatch(&app, Channel::Dapp, r#"{"method":"accounts"}"#)
            .is_err()
    );
    owner(
        &mut session,
        json!({"method":"unlock","password":"synthetic-password"}),
    );
    assert_eq!(
        session
            .dispatch(&app, Channel::Dapp, r#"{"method":"accounts"}"#)
            .unwrap(),
        visible
    );
    owner(
        &mut session,
        json!({"method":"set_grant","principal":app,"grant":null}),
    );
    assert!(
        session
            .dispatch(&app, Channel::Dapp, r#"{"method":"accounts"}"#)
            .is_err()
    );
    owner(&mut session, json!({"method":"lock"}));
    drop(session);
    let mut reopened = Session::new(&path).unwrap();
    assert_eq!(
        owner(&mut reopened, json!({"method":"state"}))["accounts"],
        Value::Null
    );
    owner(
        &mut reopened,
        json!({"method":"unlock","password":"synthetic-password"}),
    );
    assert!(
        reopened
            .dispatch(&app, Channel::Dapp, r#"{"method":"accounts"}"#)
            .is_err()
    );
}

#[test]
fn access_request_requires_owner_consent_and_survives_only_as_a_durable_grant() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v03.sqlite");
    let mut session = Session::new(&path).unwrap();
    owner(
        &mut session,
        json!({"method":"create","password":"fixture"}),
    );
    let account = owner(
        &mut session,
        json!({"method":"generate_account","label":"Private owner label"}),
    )["account"]
        .clone();
    let app = module("requester");
    let request =
        json!({"method":"request_access","scopes":["Accounts","Transactions"]}).to_string();
    let pending = session
        .dispatch_at(&app, Channel::Dapp, &request, 100)
        .unwrap();
    let id = pending["id"].clone();
    assert!(
        session
            .dispatch_at(&app, Channel::Dapp, r#"{"method":"accounts"}"#, 101)
            .is_err()
    );
    let status = json!({"method":"access_status","id":id}).to_string();
    assert!(
        session
            .dispatch_at(&module("imposter"), Channel::Dapp, &status, 101)
            .is_err()
    );
    let decision=json!({"method":"decide_access","id":id,"accounts":[account],"scopes":["Accounts"],"approve":true}).to_string();
    assert!(
        session
            .dispatch_at(&app, Channel::Owner, &decision, 101)
            .is_err()
    );
    assert!(
        session
            .dispatch_at(&module(OWNER_MODULE), Channel::Dapp, &decision, 101)
            .is_err()
    );
    let before = std::fs::read(&path).unwrap();
    let invalid=json!({"method":"decide_access","id":id,"accounts":[crate::AccountId::from_bytes([9;32])],"scopes":["Accounts"],"approve":true}).to_string();
    assert!(
        session
            .dispatch_at(&module(OWNER_MODULE), Channel::Owner, &invalid, 101)
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    session
        .dispatch_at(&module(OWNER_MODULE), Channel::Owner, &decision, 102)
        .unwrap();
    let approved = session
        .dispatch_at(&app, Channel::Dapp, &status, 103)
        .unwrap();
    assert_eq!(
        approved,
        json!({"state":"approved","accounts":[account],"scopes":["Accounts"]})
    );
    assert!(
        session
            .dispatch_at(&module(OWNER_MODULE), Channel::Owner, &decision, 104)
            .is_err()
    );
    let pending2 = session
        .dispatch_at(&app, Channel::Dapp, &request, 105)
        .unwrap();
    session
        .dispatch_at(
            &module(OWNER_MODULE),
            Channel::Owner,
            r#"{"method":"lock"}"#,
            106,
        )
        .unwrap();
    session
        .dispatch_at(
            &module(OWNER_MODULE),
            Channel::Owner,
            r#"{"method":"unlock","password":"fixture"}"#,
            107,
        )
        .unwrap();
    assert!(
        session
            .dispatch_at(&app, Channel::Dapp, &status, 108)
            .is_err()
    );
    assert!(
        session
            .dispatch_at(
                &app,
                Channel::Dapp,
                &json!({"method":"access_status","id":pending2["id"]}).to_string(),
                108
            )
            .is_err()
    );
    assert_eq!(
        session
            .dispatch_at(&app, Channel::Dapp, r#"{"method":"accounts"}"#, 108)
            .unwrap()["accounts"],
        json!([account])
    );
    let fresh = session
        .dispatch_at(&app, Channel::Dapp, &request, 109)
        .unwrap();
    assert_ne!(fresh["id"], pending2["id"]);
    assert!(
        session
            .dispatch_at(
                &app,
                Channel::Dapp,
                &json!({"method":"access_status","id":fresh["id"]}).to_string(),
                409
            )
            .is_err()
    );
}
