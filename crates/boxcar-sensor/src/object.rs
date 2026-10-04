// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The eBPF object `build.rs` built, embedded; empty when `AYA_BUILD_SKIP`
//! was set, which the loader reports as `degraded`.

/// The object, aligned as the loader needs it.
pub static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/boxcar-sensor"));

#[cfg(test)]
mod tests {
    use boxcar_sensor_common::programs::{LICENSE, MAPS, PROGRAMS};

    use super::OBJECT;

    /// The object this binary carries is the sensor's: every program, every
    /// map, the dual licence. With `AYA_BUILD_SKIP` there is no object, and
    /// the test says so rather than failing.
    #[test]
    fn the_embedded_object_is_the_sensors_or_empty() {
        if OBJECT.is_empty() {
            eprintln!("skipped: built with AYA_BUILD_SKIP, no eBPF object");
            return;
        }
        let object = aya_obj::Object::parse(OBJECT).expect("the object parses");
        assert_eq!(object.license.to_str().unwrap(), LICENSE);
        for program in PROGRAMS {
            assert!(
                object.programs.contains_key(program.name),
                "{} is missing from {:?}",
                program.name,
                object.programs.keys().collect::<Vec<_>>()
            );
        }
        for (name, map_type) in MAPS {
            let map = object.maps.get(name).unwrap_or_else(|| {
                panic!(
                    "{name} is missing from {:?}",
                    object.maps.keys().collect::<Vec<_>>()
                )
            });
            assert_eq!(map.map_type(), map_type, "{name}");
        }
    }
}
