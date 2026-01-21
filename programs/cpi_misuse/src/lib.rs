pub mod vulnerable;
pub mod secure;

#[cfg(not(feature = "no-entrypoint"))]
pub use vulnerable::entry;
