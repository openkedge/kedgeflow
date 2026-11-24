//! Run as a disposable example on the original bdf6fa3 source, never in the new build.
use chrono::{DateTime, SecondsFormat, Utc};
use cedar_policy::{Context, Entities, Expression, Request};
use serde_json::{json, Value};
use std::str::FromStr;
fn main() {
    let mut millis = vec![i64::MIN, i64::MAX, -1, 0, 1, -1001, 999, 1000,
        -62167219200000, -62198755200000, 253402300799999, 253402300800000,
        1483228799999, 1483228800000, 1740000000123];
    for at in [DateTime::<Utc>::MIN_UTC.timestamp_millis(), DateTime::<Utc>::MAX_UTC.timestamp_millis()] {
        millis.extend([at - 1, at, at + 1]);
    }
    let formats: Vec<_> = millis.iter().map(|at| json!({"millis":at,
        "text":DateTime::<Utc>::from_timestamp_millis(*at).map(|x|x.to_rfc3339_opts(SecondsFormat::Millis,true)),
        "nanos":DateTime::<Utc>::from_timestamp_millis(*at).map(|x|x.to_rfc3339_opts(SecondsFormat::Nanos,true))})).collect();
    let strings = ["1970-01-01T00:00:00Z", "1969-12-31T23:59:59.999999999Z",
        "2024-02-29T12:34:56.123456789Z", "2024-02-29t12:34:56z", "2024-02-29 12:34:56Z",
        "2024-02-29T12:34:56.123456789123Z", "2024-02-29T12:34:56+23:59",
        "2024-02-29T12:34:56-00:00", "0000-01-01T00:00:00+01:00",
        "9999-12-31T23:59:59-01:00", "2016-12-31T23:59:60Z",
        "2016-12-31T23:59:60.123456789Z", "2017-01-01T00:59:60+01:00",
        "2024-01-01T12:34:60Z", "2024-02-30T00:00:00Z", "2024-01-01T24:00:00Z",
        "+10000-01-01T00:00:00Z", "-0001-01-01T00:00:00Z", "2024-01-01", "", "éééééééé60Z"];
    let parsed: Vec<_> = strings.iter().map(|s| {
        let date=DateTime::parse_from_rfc3339(s).ok();
        json!({"input":s,"millis":date.map(|d|d.timestamp_millis()),
            "at_or_after":millis.iter().map(|at|date.is_some_and(|d|DateTime::<Utc>::from_timestamp_millis(*at).is_some_and(|t|t>=d))).collect::<Vec<_>>()})
    }).collect();
    let request=Request::new("User::\"wire\"".parse().unwrap(), "Action::\"read\"".parse().unwrap(),
        "Resource::\"wire\"".parse().unwrap(),Context::empty(),None).unwrap();
    let entities=Entities::empty();
    let mut expressions=vec![];
    for date in ["0000-01-01", "0001-01-01", "1900-02-29", "2000-02-29", "2024-02-29", "2024-10-15", "9999-12-31"] {
        expressions.push(format!("datetime(\"{date}\")"));
        for clock in ["00:00:00", "11:38:02", "23:59:59", "23:59:60", "24:00:00"] {
            for tail in ["Z", ".101Z", "+1134", "-1134", "+2359", "-2359", "+2400"] {
                expressions.push(format!("datetime(\"{date}T{clock}{tail}\")"));
            }
        }
    }
    for expr in [
        "datetime(\"1969-12-31T23:59:59.999Z\").toDate()",
        "datetime(\"1969-12-31T23:59:59.999Z\").toTime()",
        "datetime(\"2024-10-15\").offset(duration(\"-1ms\"))",
        "datetime(\"2024-10-15\").durationSince(datetime(\"2024-10-14\"))",
        "datetime(\"1970-01-01\").offset(duration(\"9223372036854775807ms\"))",
        "datetime(\"1970-01-01\").offset(duration(\"-9223372036854775808ms\"))",
        "datetime(\"1970-01-01\").offset(duration(\"9223372036854775807ms\")).offset(duration(\"1ms\"))",
    ] {expressions.push(expr.into());}
    let cedar:Vec<_>=expressions.iter().map(|s|{
        let value=Expression::from_str(s).ok().and_then(|e|cedar_policy::eval_expression(&request,&entities,&e).ok());
        json!({"expression":s,"value":value.map(|v|v.to_string())})
    }).collect();
    let report:Value=json!({"format":"kedgeflow-legacy-time-wire-v1",
        "source_commit":"bdf6fa38ea915f44387b0c0240bbd4d8b51f1e52",
        "chrono":"0.4.45","cedar":"4.7.1","formats":formats,"parsed":parsed,"cedar":cedar,
        "scope":"Public timestamp and expression compatibility fixtures; no execution or acceptance authority"});
    println!("{}",serde_json::to_string_pretty(&report).unwrap());
}
