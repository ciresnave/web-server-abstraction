//! Database integration helpers.

use std::collections::HashMap;

/// Simple database error for basic functionality
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Query error: {0}")]
    Query(String),
}

/// Database pool stats for monitoring
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_connections: u32,
    pub active_connections: u32,
}

/// Simple database value type
#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseValue {
    Text(String),
    Integer(i64),
    Real(f64),
    Null,
}

/// Database row representation
#[derive(Debug, Clone)]
pub struct Row {
    columns: HashMap<String, DatabaseValue>,
}

impl Row {
    pub fn new() -> Self {
        Self {
            columns: HashMap::new(),
        }
    }

    /// Get a value from the row by column name
    pub fn get(&self, column: &str) -> Option<&DatabaseValue> {
        self.columns.get(column)
    }

    /// Set a value in the row
    pub fn set(&mut self, column: String, value: DatabaseValue) {
        self.columns.insert(column, value);
    }

    /// Check if a column exists
    pub fn contains_key(&self, column: &str) -> bool {
        self.columns.contains_key(column)
    }

    /// Get all column names
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.columns.keys()
    }

    /// Get the number of columns
    pub fn len(&self) -> usize {
        self.columns.len()
    }

    /// Check if the row is empty
    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }
}

impl Default for Row {
    fn default() -> Self {
        Self::new()
    }
}

/// Mock database for testing
pub struct MockDatabase;

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite://memory".to_string(),
            max_connections: 10,
        }
    }
}

/// Connection pool trait
pub trait ConnectionPool {
    fn stats(&self) -> PoolStats;
}

/// Database connection trait
pub trait DatabaseConnection {
    fn execute(&mut self, query: &str) -> Result<u64, DatabaseError>;
}

/// Query builder for dynamic queries
pub struct QueryBuilder {
    query: String,
}

impl QueryBuilder {
    pub fn new() -> Self {
        Self {
            query: String::new(),
        }
    }

    pub fn select(mut self, columns: &str) -> Self {
        self.query = format!("SELECT {}", columns);
        self
    }

    pub fn from(mut self, table: &str) -> Self {
        self.query.push_str(&format!(" FROM {}", table));
        self
    }

    pub fn build(self) -> String {
        self.query
    }
}

impl Default for QueryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Transaction handle
pub struct Transaction;

/// Database value conversion trait
pub trait FromDatabaseValue {
    fn from_database_value(value: &DatabaseValue) -> Option<Self>
    where
        Self: Sized;
}

impl FromDatabaseValue for String {
    fn from_database_value(value: &DatabaseValue) -> Option<Self> {
        match value {
            DatabaseValue::Text(s) => Some(s.clone()),
            _ => None,
        }
    }
}

impl FromDatabaseValue for i64 {
    fn from_database_value(value: &DatabaseValue) -> Option<Self> {
        match value {
            DatabaseValue::Integer(i) => Some(*i),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_row_operations() {
        let mut row = Row::new();
        assert!(row.is_empty());
        assert_eq!(row.len(), 0);

        // Test setting values
        row.set("id".to_string(), DatabaseValue::Integer(42));
        row.set("name".to_string(), DatabaseValue::Text("Alice".to_string()));
        row.set("score".to_string(), DatabaseValue::Real(95.5));

        assert!(!row.is_empty());
        assert_eq!(row.len(), 3);

        // Test getting values
        assert_eq!(row.get("id"), Some(&DatabaseValue::Integer(42)));
        assert_eq!(
            row.get("name"),
            Some(&DatabaseValue::Text("Alice".to_string()))
        );
        assert_eq!(row.get("score"), Some(&DatabaseValue::Real(95.5)));
        assert_eq!(row.get("missing"), None);

        // Test contains_key
        assert!(row.contains_key("id"));
        assert!(row.contains_key("name"));
        assert!(!row.contains_key("missing"));

        // Test keys iteration
        let keys: Vec<&String> = row.keys().collect();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&&"id".to_string()));
        assert!(keys.contains(&&"name".to_string()));
        assert!(keys.contains(&&"score".to_string()));
    }
}
