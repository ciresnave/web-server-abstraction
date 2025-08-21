//! Session management for user sessions and authentication.

use crate::types::{Cookie, Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub data: HashMap<String, String>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

impl Session {
    /// Create a new session
    pub fn new(duration: Duration) -> Self {
        let now = SystemTime::now();
        Self {
            id: Uuid::new_v4().to_string(),
            data: HashMap::new(),
            created_at: now,
            expires_at: now + duration,
        }
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    /// Extend session expiration
    pub fn extend(&mut self, duration: Duration) {
        self.expires_at = SystemTime::now() + duration;
    }

    /// Get a value from session data
    pub fn get(&self, key: &str) -> Option<&String> {
        self.data.get(key)
    }

    /// Set a value in session data
    pub fn set(&mut self, key: String, value: String) {
        self.data.insert(key, value);
    }

    /// Remove a value from session data
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.data.remove(key)
    }

    /// Clear all session data
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

/// Session store trait
pub trait SessionStore: Send + Sync {
    /// Get a session by ID
    fn get(&self, session_id: &str) -> Option<Session>;

    /// Store a session
    fn set(&self, session: Session);

    /// Remove a session
    fn remove(&self, session_id: &str);

    /// Clean up expired sessions
    fn cleanup_expired(&self);
}

/// In-memory session store
#[derive(Debug)]
pub struct MemorySessionStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore for MemorySessionStore {
    fn get(&self, session_id: &str) -> Option<Session> {
        let sessions = self.sessions.read().unwrap();
        sessions.get(session_id).cloned()
    }

    fn set(&self, session: Session) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.insert(session.id.clone(), session);
    }

    fn remove(&self, session_id: &str) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(session_id);
    }

    fn cleanup_expired(&self) {
        let mut sessions = self.sessions.write().unwrap();
        let now = SystemTime::now();
        sessions.retain(|_, session| session.expires_at > now);
    }
}

/// Session manager
pub struct SessionManager {
    store: Box<dyn SessionStore>,
    cookie_name: String,
    session_duration: Duration,
    secure: bool,
    http_only: bool,
}

impl SessionManager {
    /// Create a new session manager
    pub fn new(store: Box<dyn SessionStore>) -> Self {
        Self {
            store,
            cookie_name: "session_id".to_string(),
            session_duration: Duration::from_secs(24 * 60 * 60), // 24 hours
            secure: false,
            http_only: true,
        }
    }

    /// Create with memory store
    pub fn memory() -> Self {
        Self::new(Box::new(MemorySessionStore::new()))
    }

    /// Set cookie name
    pub fn cookie_name(mut self, name: String) -> Self {
        self.cookie_name = name;
        self
    }

    /// Set session duration
    pub fn duration(mut self, duration: Duration) -> Self {
        self.session_duration = duration;
        self
    }

    /// Set secure flag for cookies
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// Set http_only flag for cookies
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// Get session from request
    pub fn get_session(&self, request: &Request) -> Option<Session> {
        let cookie = request.cookie(&self.cookie_name)?;
        let session = self.store.get(&cookie.value)?;

        if session.is_expired() {
            self.store.remove(&session.id);
            return None;
        }

        Some(session)
    }

    /// Create a new session
    pub fn create_session(&self) -> Session {
        Session::new(self.session_duration)
    }

    /// Save session and return response with session cookie
    pub fn save_session(&self, mut session: Session, response: Response) -> Response {
        // Extend session if it's about to expire
        if session
            .expires_at
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO)
            < self.session_duration / 4
        {
            session.extend(self.session_duration);
        }

        let cookie = Cookie::new(&self.cookie_name, &session.id)
            .path("/")
            .http_only(self.http_only)
            .secure(self.secure)
            .max_age(self.session_duration);

        self.store.set(session);
        response.cookie(cookie)
    }

    /// Destroy session
    pub fn destroy_session(&self, request: &Request, mut response: Response) -> Response {
        if let Some(cookie) = request.cookie(&self.cookie_name) {
            self.store.remove(&cookie.value);

            // Send cookie with expired date to clear it
            let expired_cookie = Cookie::new(&self.cookie_name, "")
                .path("/")
                .max_age(Duration::ZERO);

            response = response.cookie(expired_cookie);
        }
        response
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&self) {
        self.store.cleanup_expired();
    }
}

/// Session middleware extension trait
pub trait SessionExt {
    /// Get or create session
    fn session(&self, manager: &SessionManager) -> Session;
}

impl SessionExt for Request {
    fn session(&self, manager: &SessionManager) -> Session {
        manager
            .get_session(self)
            .unwrap_or_else(|| manager.create_session())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new(Duration::from_secs(3600));
        assert!(!session.is_expired());
        assert_eq!(session.data.len(), 0);
    }

    #[test]
    fn test_session_data() {
        let mut session = Session::new(Duration::from_secs(3600));

        session.set("user_id".to_string(), "123".to_string());
        assert_eq!(session.get("user_id"), Some(&"123".to_string()));

        session.remove("user_id");
        assert_eq!(session.get("user_id"), None);
    }

    #[test]
    fn test_memory_store() {
        let store = MemorySessionStore::new();
        let session = Session::new(Duration::from_secs(3600));
        let session_id = session.id.clone();

        store.set(session);
        assert!(store.get(&session_id).is_some());

        store.remove(&session_id);
        assert!(store.get(&session_id).is_none());
    }

    #[test]
    fn test_session_manager() {
        let manager = SessionManager::memory()
            .cookie_name("test_session".to_string())
            .duration(Duration::from_secs(1800));

        let session = manager.create_session();
        assert!(!session.is_expired());
    }
}
