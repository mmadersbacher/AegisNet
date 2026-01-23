use sea_orm::{Database, DatabaseConnection, ConnectionTrait};
use std::env;

pub async fn connect() -> Result<DatabaseConnection, sea_orm::DbErr> {
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    
    // Create connection options if needed
    // let mut opt = ConnectOptions::new(&db_url);
    
    let db = Database::connect(db_url).await?;
    tracing::info!("Connected to the database");
    
    create_schema(&db).await?;

    Ok(db)
}

async fn create_schema(db: &DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    use sea_orm::{schema::Schema, DbBackend};
    use crate::entities::{user, log};

    let builder = db.get_database_backend();
    let schema = Schema::new(builder);

    let stmt = schema.create_table_from_entity(user::Entity).if_not_exists().to_owned();
    db.execute(builder.build(&stmt)).await?;

    let stmt_log = schema.create_table_from_entity(log::Entity).if_not_exists().to_owned();
    db.execute(builder.build(&stmt_log)).await?;
    
    tracing::info!("Schema initialized (Users & Logs tables)");
    Ok(())
}
