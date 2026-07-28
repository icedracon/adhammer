#![no_main]
//! Fuzz the endpoint-mapper response parsers (tower/port + ept_map reply). These consume bytes
//! from the remote DC's endpoint mapper.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = adhammer_dcerpc::epm::parse_tower_port(data);
    let _ = adhammer_dcerpc::epm::decode_map_response(data);
});
