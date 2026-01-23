use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "logs")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(index)]
    pub source: String,       // e.g., "firewall-1", "linux-server-2"
    pub level: String,        // INFO, WARN, ERROR, CRITICAL
    pub message: String,      // Normalized message
    #[sea_orm(column_type = "Text")]
    pub raw_content: String,  // Original log line
    pub event_time: DateTime, // When the event happened
    pub received_at: DateTime,// When we received it
    pub metadata: Option<String>, // JSON string for extra fields
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
