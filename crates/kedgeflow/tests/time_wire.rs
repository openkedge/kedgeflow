//! Compare all Cedar datetime results to the captured pre-migration implementation.
use cedar_policy::{Context, Entities, Expression, Request};
use serde_json::Value;
use std::str::FromStr;

#[test]
fn cedar_datetime_preserves_legacy_calendar_arithmetic_and_errors() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../fixtures/compat/legacy-time-wire.json"
    ))
    .unwrap();
    let request = Request::new(
        "User::\"wire\"".parse().unwrap(),
        "Action::\"read\"".parse().unwrap(),
        "Resource::\"wire\"".parse().unwrap(),
        Context::empty(),
        None,
    )
    .unwrap();
    let entities = Entities::empty();
    for row in corpus["cedar"].as_array().unwrap() {
        let input = row["expression"].as_str().unwrap();
        let actual = Expression::from_str(input)
            .ok()
            .and_then(|e| cedar_policy::eval_expression(&request, &entities, &e).ok())
            .map(|v| v.to_string());
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            row["value"],
            "{input}"
        );
    }
}
