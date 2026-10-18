//! Offline detection contract shared by the trusted broker and report importer.
//! File scanners are invoked only by the disposable guest agent, never by this library.
mod config;
mod model;
pub mod observables;
pub mod validation;
pub use config::*;
pub use model::*;
#[cfg(test)]
mod tests;
