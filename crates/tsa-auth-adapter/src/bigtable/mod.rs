mod adapter;
mod client;
mod repositories;
mod schema;

pub use adapter::BigtableAdapter;
pub use client::BigtableClient;
pub use schema::BigtableSchemaManager;

pub const TABLE_NAME: &str = "tsa";
pub const CF_DATA: &str = "d";
