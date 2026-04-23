use anyhow::Result;
use std::collections::BTreeMap;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_core::{w, PCWSTR};

pub mod cache;
mod utility;

use cache::Type;

#[derive(Debug)]
pub enum Version {
    Relative,
    Absolute,
}

#[derive(Debug)]
pub struct Signature {
    name: &'static str,
    pattern: &'static str,
    module: PCWSTR,
    version: Version,
    typ: Type,
    offset: i32,
}

impl Signature {
    pub const fn new(
        name: &'static str,
        pattern: &'static str,
        module: PCWSTR,
        version: Version,
        typ: Type,
        offset: i32,
    ) -> Self {
        Self {
            name,
            pattern,
            module,
            version,
            typ,
            offset,
        }
    }

    pub fn get_pattern(&self) -> Vec<u8> {
        self.pattern
            .split_ascii_whitespace()
            .into_iter()
            .map(|s| {
                if let Ok(byte) = u8::from_str_radix(s, 16) {
                    byte
                } else {
                    0xCC
                }
            })
            .collect()
    }
}

#[derive(Debug)]
pub struct SigScanner {
    pub sigs: BTreeMap<String, cache::CachedSignature>,
}

impl SigScanner {
    pub fn new(sigs: &[Signature]) -> Result<Self> {
        let sigs = Self::scan(sigs)?;

        Ok(Self { sigs })
    }

    fn scan(sigs: &[Signature]) -> Result<BTreeMap<String, cache::CachedSignature>> {
        let mut cache = cache::Cache::new()?;
        let mut map = BTreeMap::new();

        for sig in sigs.iter() {
            let module = unsafe { GetModuleHandleW(sig.module)? };

            if let Some(mut cached_sig) = cache.find(sig.name) {
                cached_sig.module_base = module.0.addr();

                map.insert(sig.name.to_string(), cached_sig);

                log::info!("Found cached_sig {}", sig.name);

                continue;
            }

            let pattern = sig.get_pattern();
            let p_len = pattern.len();
            let module_size = utility::get_module_size(module);
            let module_base = module.0.addr();

            let bytes: *const [u8] = std::ptr::slice_from_raw_parts(module.0 as _, module_size);

            // we are searching by pattern size
            for i in p_len..module_size {
                let mut found = true;

                for j in 0..p_len {
                    let byte = unsafe { (&*bytes)[i + j] };

                    if pattern[j] != byte && pattern[j] != 0xCC {
                        found = false;
                        break;
                    }
                }

                if found == true {
                    let rva = match sig.version {
                        Version::Relative => {
                            let address = (i as i32 + sig.offset) as usize;

                            let offset = unsafe {
                                i32::from_le_bytes(
                                    (&*bytes)[address..address + 4].try_into().unwrap(),
                                )
                            };

                            (address as i32 + offset + 4) as usize
                        }
                        Version::Absolute => i,
                    };

                    log::info!(
                        "Found pattern {} 0x{:X} at offset {i:X}",
                        sig.name,
                        rva + module_base
                    );

                    map.insert(
                        sig.name.to_string(),
                        cache::CachedSignature::new(rva, sig.typ, module_base),
                    );

                    break;
                }
            }
        }

        cache.store(&map)?;

        Ok(map)
    }
}
