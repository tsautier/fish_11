//! FiSH 10 DLL Interface Module
//!
//! This module contains all the DLL interface functions for FiSH 10 legacy compatibility.

pub mod fish10_decryptmsg;
pub mod fish10_delkey;
pub mod fish10_encryptmsg;
pub mod fish10_gettopicsetting;
pub mod fish10_haskey;
pub mod fish10_register_engine;
pub mod fish10_setkey;
pub mod fish10_settopic;
pub mod fish10_settopicsetting;

pub use fish10_settopic::{FiSH10_GetTopic, FiSH10_RemoveTopic, FiSH10_SetTopic};
