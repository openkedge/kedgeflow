#!/usr/bin/env python3
"""Reproduce the Cedar datetime patch from its checksum-pinned public crate."""

import argparse
import hashlib
import io
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "cedar-policy-core-4.7.1"
UPSTREAM_SHA256 = "862e353fda86c0486dc6649aeaabda7495ff143d9a68b5c9994f31532e2a5bb4"
SERDE_SHA256 = "df9adc193c780ef8f159aee8b61e2d5801aaa555e6eb0947fe45530ec506296f"


def replace(raw, before, after, count=1):
    if raw.count(before) != count:
        raise ValueError("upstream patch context differs")
    return raw.replace(before, after)


def patch(name, raw):
    if name == "Cargo.toml":
        raw = replace(raw, 'rust-version = "1.85"', 'rust-version = "1.88"')
        raw = replace(raw, 'datetime = ["dep:chrono"]', 'datetime = ["dep:time"]')
        raw = replace(
            raw,
            '[dependencies.chrono]\nversion = "0.4.42"\noptional = true\ndefault-features = false',
            '[dependencies.time]\nversion = "=0.3.55"\noptional = true\n'
            'default-features = false\nfeatures = ["large-dates", "parsing"]',
        )
    elif name == "Cargo.toml.orig":
        raw = replace(raw, 'rust-version.workspace = true', 'rust-version = "1.88"')
        raw = replace(raw, "# datetime extension requires chrono", "# datetime extension uses time")
        raw = replace(
            raw,
            'chrono = { version = "0.4.42", optional = true, default-features = false}',
            'time = { version = "=0.3.55", optional = true, default-features = false, '
            'features = ["large-dates", "parsing"] }',
        )
        raw = replace(raw, 'datetime = ["dep:chrono"]', 'datetime = ["dep:time"]')
    elif name == "src/extensions/datetime.rs":
        raw = replace(
            raw,
            "use chrono::{NaiveDate, NaiveDateTime, NaiveTime, TimeDelta};",
            "use time::{Date, Month, PlainDateTime, SignedDuration, Time};",
        )
        raw = replace(raw, "NaiveDateTime", "PlainDateTime", count=15)
        raw = replace(
            raw,
            "        let delta = chrono::DateTime::from_naive_utc_and_offset(value, chrono::Utc)\n"
            "            - chrono::DateTime::UNIX_EPOCH;\n        Self {\n"
            "            epoch: delta.num_milliseconds(),\n        }",
            "        // Parsed Cedar datetimes have exact millisecond precision.\n"
            "        Self {\n"
            "            epoch: (value.assume_utc().unix_timestamp_nanos() / 1_000_000) as i64,\n"
            "        }",
        )
        raw = replace(
            raw,
            "        NaiveDate::from_ymd_opt(\n            year.parse().unwrap(),\n"
            "            month.parse().unwrap(),\n            day.parse().unwrap(),\n        )\n"
            "        .ok_or_else(|| DateTimeParseError::InvalidDate(date_str.into()))",
            "        let month = Month::try_from(month.parse::<u8>().unwrap())\n"
            "            .map_err(|_| DateTimeParseError::InvalidDate(date_str.into()))?;\n"
            "        Date::from_calendar_date(year.parse().unwrap(), month, day.parse().unwrap())\n"
            "            .map_err(|_| DateTimeParseError::InvalidDate(date_str.into()))",
        )
        raw = replace(raw, "NaiveTime::from_hms_opt(0, 0, 0).unwrap()", "Time::MIDNIGHT")
        raw = replace(raw, "let (h, m, sec): (u32, u32, u32)", "let (h, m, sec): (u8, u8, u8)")
        raw = replace(raw, "let ms: u32 =", "let ms: u16 =")
        raw = replace(
            raw,
            "NaiveTime::from_hms_milli_opt(h, m, sec, ms)\n"
            "        .ok_or_else(|| DateTimeParseError::InvalidHMS(hms_str[1..].into()))?",
            "Time::from_hms_milli(h, m, sec, ms)\n"
            "        .map_err(|_| DateTimeParseError::InvalidHMS(hms_str[1..].into()))?",
        )
        raw = replace(
            raw,
            "Result<TimeDelta, DateTimeParseError>",
            "Result<SignedDuration, DateTimeParseError>",
        )
        raw = replace(
            raw,
            "TimeDelta::new(-offset_in_secs, 0).unwrap()",
            "SignedDuration::seconds(-offset_in_secs)",
        )
        raw = replace(raw, "TimeDelta::default()", "SignedDuration::default()")
        raw = replace(
            raw,
            "    use chrono::PlainDateTime;",
            "    fn expected_datetime(s: &str) -> PlainDateTime {\n"
            "        PlainDateTime::parse(s, "
            "&time::format_description::well_known::Iso8601::DEFAULT).unwrap()\n    }",
        )
        raw = replace(raw, 'PlainDateTime::from_str("', 'expected_datetime("', count=9)
        # These nine pre-existing expectations now use the maintained parser.
        import re

        raw, changed = re.subn(r'(expected_datetime\("[^"\n]+"\))\.unwrap\(\)', r"\1", raw)
        if changed != 9:
            raise ValueError("upstream test patch context differs")
        raw = replace(raw, "use std::{str::FromStr, sync::Arc};", "use std::sync::Arc;")
    return raw


def patch_serde(name, raw):
    if name in {"Cargo.toml", "Cargo.toml.orig"}:
        raw = replace(raw, 'chrono_0_4 = ["dep:chrono_0_4"]', "chrono_0_4 = []")
        for feature in ("alloc", "clock", "std"):
            entry = f'"chrono_0_4?/{feature}", '
            if name == "Cargo.toml":
                entry = f'    "chrono_0_4?/{feature}",\n'
            raw = replace(raw, entry, "")
        if name == "Cargo.toml":
            raw = replace(
                raw,
                '[dependencies.chrono_0_4]\nversion = "0.4.20"\nfeatures = ["serde"]\n'
                'optional = true\ndefault-features = false\npackage = "chrono"\n\n',
                "",
            )
        else:
            raw = replace(
                raw,
                'chrono_0_4 = { package = "chrono", version = "0.4.20", optional = true, '
                'default-features = false, features = ["serde"] }\n',
                "",
            )
    elif name == "src/lib.rs":
        marker = (
            '#[cfg(feature = "chrono_0_4")]\n#[cfg_attr(docsrs, doc(cfg(feature = "chrono_0_4")))]'
        )
        raw = replace(
            raw,
            marker,
            '#[cfg(feature = "chrono_0_4")]\n'
            'compile_error!("Kedgeflow excludes unused Chrono conversions; '
            'use the time integration");\n'
            + marker,
        )
    return raw


def vendor(archive, destination, *, package=PACKAGE, checksum=UPSTREAM_SHA256, patcher=patch):
    blob = archive.read_bytes()
    if hashlib.sha256(blob).hexdigest() != checksum:
        raise ValueError("public upstream crate checksum mismatch")
    files = {}
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as stream:
        for entry in stream:
            path = Path(entry.name)
            if path.parts[0] != package or path.is_absolute() or ".." in path.parts:
                raise ValueError("invalid upstream archive path")
            if entry.isdir():
                continue
            if not entry.isfile() or entry.size > 8 << 20:
                raise ValueError("invalid upstream archive entry")
            name = str(Path(*path.parts[1:]))
            if name in files:
                raise ValueError("duplicate upstream archive path")
            original = stream.extractfile(entry).read()
            changed = (
                patcher(name, original.decode()).encode()
                if name
                in {"Cargo.toml", "Cargo.toml.orig", "src/extensions/datetime.rs", "src/lib.rs"}
                else original
            )
            files[name] = (original, changed)
    destination.mkdir(parents=True, exist_ok=False)
    inventory = {}
    for name, (original, changed) in sorted(files.items()):
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(changed)
        inventory[name] = {
            "upstream_sha256": hashlib.sha256(original).hexdigest(),
            "sha256": hashlib.sha256(changed).hexdigest(),
        }
    provenance = {
        "format": "kedgeflow-vendored-source-v1",
        "package": package.rsplit("-", 1)[0],
        "version": package.rsplit("-", 1)[1],
        "upstream_crate_sha256": checksum,
        "upstream_url": (
            f"https://static.crates.io/crates/{package.rsplit('-', 1)[0]}/{package}.crate"
        ),
        "patch_scope": (
            "Datetime calendar construction and epoch conversion only; "
            "all Cedar extensions retained"
            if package == PACKAGE
            else (
                "Remove unused optional Chrono serialization; "
                "explicit activation fails compilation"
            )
        ),
        "independent_security_acceptance": "BLOCKED_EXTERNAL_INPUT",
        "files": inventory,
    }
    return provenance


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--serde-archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    packages = [
        vendor(args.archive, args.output / PACKAGE),
        vendor(
            args.serde_archive,
            args.output / "serde_with-3.24.0",
            package="serde_with-3.24.0",
            checksum=SERDE_SHA256,
            patcher=patch_serde,
        ),
    ]
    record = args.output / "provenance.json"
    record.write_text(
        json.dumps({"format": "kedgeflow-vendored-sources-v1", "packages": packages}, indent=2)
        + "\n"
    )
    print(
        json.dumps(
            {
                "packages": len(packages),
                "provenance_sha256": hashlib.sha256(record.read_bytes()).hexdigest(),
            }
        )
    )
