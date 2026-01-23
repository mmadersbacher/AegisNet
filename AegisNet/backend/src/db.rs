use sea_orm::{Database, DatabaseConnection};
use std::env;

pub async fn connect() -> Result<DatabaseConnection, sea_orm::DbErr> {
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    
    // Create connection options if needed
    // let mut opt = ConnectOptions::new(&db_url);
    
    let db = Database::connect(db_url).await?;
    tracing::info!("Connected to the database");
    
    Ok(db)
}
