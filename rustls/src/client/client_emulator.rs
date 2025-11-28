#[derive(Clone, Debug)]
#[allow(missing_docs, clippy::exhaustive_structs)]
pub struct BrowserEmulator {
    pub browser_type: BrowserType,
    pub version: BrowserVersion,
}

#[derive(Clone, Debug)]
#[allow(missing_docs, clippy::exhaustive_structs)]
pub struct BrowserVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

#[derive(Clone, Debug)]
#[allow(clippy::exhaustive_enums, missing_docs)]
pub enum BrowserType {
    Chrome,
    Firefox,
}
