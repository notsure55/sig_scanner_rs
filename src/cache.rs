use anyhow::Result;
use log::log;
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;

#[derive(PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
pub enum Type {
    Global,
    Function,
    Offset,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CachedSignature {
    pub rva: usize,
    pub typ: Type,
    pub module_base: usize,
}

impl CachedSignature {
    pub fn new(rva: usize, typ: Type, module_base: usize) -> Self {
        Self {
            rva,
            typ,
            module_base,
        }
    }

    pub fn addr(&self) -> usize {
        self.rva + self.module_base
    }

    pub fn offset<T: bytemuck::Pod>(&self) -> Option<usize> {
        if let Type::Offset = self.typ {
            let addr = self.addr();
            let value: usize = unsafe { std::mem::transmute_copy(&*(addr as *const T)) };
            Some(value)
        } else {
            None
        }
    }
}

pub struct Cache {
    cached: BTreeMap<String, CachedSignature>,
}

impl Cache {
    pub fn new() -> Result<Self> {
        let cache = std::fs::read_to_string("cache.json");

        if cache.is_err() {
            let cached = BTreeMap::new();
            Ok(Self { cached })
        } else {
            let cache = cache.unwrap();

            let cached: BTreeMap<String, CachedSignature> = serde_json::from_str(&cache)?;

            Ok(Self { cached })
        }
    }
    pub fn find(&mut self, sig_name: &str) -> Option<CachedSignature> {
        self.cached.remove(sig_name)
    }
    pub fn store(&self, map: &BTreeMap<String, CachedSignature>) -> Result<()> {
        let map = serde_json::to_string(map)?;

        let mut file = File::create("cache.json")?;

        file.write_all(map.as_bytes())?;

        Ok(())
    }
}
