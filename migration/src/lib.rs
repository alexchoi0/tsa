pub use sea_orm_migration::prelude::*;

mod m20241219_000001_create_users_table;
mod m20241219_000002_create_sessions_table;
mod m20241219_000003_create_accounts_table;
mod m20241219_000004_create_verification_tokens_table;
mod m20241219_000005_create_two_factors_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20241219_000001_create_users_table::Migration),
            Box::new(m20241219_000002_create_sessions_table::Migration),
            Box::new(m20241219_000003_create_accounts_table::Migration),
            Box::new(m20241219_000004_create_verification_tokens_table::Migration),
            Box::new(m20241219_000005_create_two_factors_table::Migration),
        ]
    }
}
