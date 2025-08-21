use std::collections::HashMap;

/// Route pattern matching for extracting path parameters
#[derive(Debug, Clone)]
pub struct Route {
    pattern: String,
    segments: Vec<RouteSegment>,
}

#[derive(Debug, Clone)]
enum RouteSegment {
    Static(String),
    Parameter(String),
    Wildcard,
}

impl Route {
    /// Create a new route pattern
    ///
    /// Supports patterns like:
    /// - `/users/{id}` - captures `id` parameter
    /// - `/users/{id}/posts/{post_id}` - captures multiple parameters
    /// - `/files/*` - wildcard matching
    pub fn new(pattern: impl Into<String>) -> Self {
        let pattern = pattern.into();
        let segments = Self::parse_pattern(&pattern);

        Self { pattern, segments }
    }

    /// Check if a path matches this route and extract parameters
    pub fn matches(&self, path: &str) -> Option<HashMap<String, String>> {
        let path_segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let mut params = HashMap::new();

        // Handle empty path
        if path_segments.len() == 1
            && path_segments[0].is_empty()
            && (self.segments.is_empty()
                || (self.segments.len() == 1
                    && matches!(self.segments[0], RouteSegment::Static(ref s) if s.is_empty())))
        {
            return Some(params);
        }

        let mut path_index = 0;
        for segment in &self.segments {
            match segment {
                RouteSegment::Static(expected) => {
                    if expected.is_empty() {
                        continue; // Skip empty segments (from leading /)
                    }
                    if path_index >= path_segments.len() || path_segments[path_index] != expected {
                        return None;
                    }
                    path_index += 1;
                }
                RouteSegment::Parameter(name) => {
                    if path_index >= path_segments.len() {
                        return None;
                    }
                    params.insert(name.clone(), path_segments[path_index].to_string());
                    path_index += 1;
                }
                RouteSegment::Wildcard => {
                    // Wildcard matches everything remaining
                    return Some(params);
                }
            }
        }

        // All segments must be consumed
        if path_index == path_segments.len() {
            Some(params)
        } else {
            None
        }
    }

    fn parse_pattern(pattern: &str) -> Vec<RouteSegment> {
        let mut segments = Vec::new();

        for segment in pattern.split('/') {
            if segment.is_empty() {
                segments.push(RouteSegment::Static(String::new()));
                continue;
            }

            if segment == "*" {
                segments.push(RouteSegment::Wildcard);
            } else if segment.starts_with('{') && segment.ends_with('}') {
                let param_name = segment.trim_start_matches('{').trim_end_matches('}');
                segments.push(RouteSegment::Parameter(param_name.to_string()));
            } else {
                segments.push(RouteSegment::Static(segment.to_string()));
            }
        }

        segments
    }

    /// Get the original pattern
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// Simple router that matches routes and extracts parameters
#[derive(Debug)]
pub struct Router<T> {
    routes: Vec<(Route, T)>,
}

impl<T> Router<T> {
    /// Create a new router
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Add a route with associated data
    pub fn add_route(&mut self, pattern: impl Into<String>, data: T) {
        let route = Route::new(pattern);
        self.routes.push((route, data));
    }

    /// Find a matching route and return the data and extracted parameters
    pub fn match_route(&self, path: &str) -> Option<(&T, HashMap<String, String>)> {
        for (route, data) in &self.routes {
            if let Some(params) = route.matches(path) {
                return Some((data, params));
            }
        }
        None
    }

    /// Get all routes
    pub fn routes(&self) -> &[(Route, T)] {
        &self.routes
    }
}

impl<T> Default for Router<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_route() {
        let route = Route::new("/users");
        assert!(route.matches("/users").is_some());
        assert!(route.matches("/users/").is_none());
        assert!(route.matches("/other").is_none());
    }

    #[test]
    fn test_parameter_route() {
        let route = Route::new("/users/{id}");

        let params = route.matches("/users/123").unwrap();
        assert_eq!(params.get("id"), Some(&"123".to_string()));

        assert!(route.matches("/users").is_none());
        assert!(route.matches("/users/123/posts").is_none());
    }

    #[test]
    fn test_multiple_parameters() {
        let route = Route::new("/users/{user_id}/posts/{post_id}");

        let params = route.matches("/users/123/posts/456").unwrap();
        assert_eq!(params.get("user_id"), Some(&"123".to_string()));
        assert_eq!(params.get("post_id"), Some(&"456".to_string()));
    }

    #[test]
    fn test_wildcard_route() {
        let route = Route::new("/files/*");

        assert!(route.matches("/files/any/path/here").is_some());
        assert!(route.matches("/files/").is_some());
        assert!(route.matches("/other/path").is_none());
    }

    #[test]
    fn test_router() {
        let mut router = Router::new();
        router.add_route("/users/{id}", "user_handler");
        router.add_route("/posts/{id}", "post_handler");

        let (handler, params) = router.match_route("/users/123").unwrap();
        assert_eq!(*handler, "user_handler");
        assert_eq!(params.get("id"), Some(&"123".to_string()));

        let (handler, params) = router.match_route("/posts/456").unwrap();
        assert_eq!(*handler, "post_handler");
        assert_eq!(params.get("id"), Some(&"456".to_string()));

        assert!(router.match_route("/unknown").is_none());
    }
}
