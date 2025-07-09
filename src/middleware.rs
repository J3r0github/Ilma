use actix_web::{dev::ServiceRequest, Error, HttpMessage, body::BoxBody};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use crate::auth::verify_jwt;
use crate::models::Claims;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use actix_web::{HttpResponse, dev::ServiceResponse, dev::Transform, dev::Service, Result, body::MessageBody};
use actix_web::dev::forward_ready;
use futures::future::{ok, Ready};
use std::rc::Rc;
use std::pin::Pin;
use futures::Future;
use std::env;
use sentry;
use log::debug;
use tokio::time::interval;

// Rate limit configuration for a specific endpoint
#[derive(Clone)]
pub struct RateLimitConfig {
    pub max_requests: usize,
    pub window_duration: Duration,
}

impl RateLimitConfig {
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_duration: Duration::from_secs(window_seconds),
        }
    }
}

// Enhanced rate limiter with per-endpoint configuration
pub struct RateLimiter {
    requests: Arc<DashMap<String, Vec<Instant>>>,
    global_config: RateLimitConfig,
    endpoint_configs: HashMap<String, RateLimitConfig>,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_seconds: u64) -> Self {
        let rate_limiter = Self {
            requests: Arc::new(DashMap::new()),
            global_config: RateLimitConfig::new(max_requests, window_seconds),
            endpoint_configs: HashMap::new(),
        };
        
        // Start cleanup task
        rate_limiter.start_cleanup_task();
        rate_limiter
    }

    pub fn with_endpoint_config(mut self, endpoint: String, config: RateLimitConfig) -> Self {
        self.endpoint_configs.insert(endpoint, config);
        self
    }

    pub fn add_endpoint_config(&mut self, endpoint: String, config: RateLimitConfig) {
        self.endpoint_configs.insert(endpoint, config);
    }

    fn get_config_for_endpoint(&self, method: &str, path: &str) -> &RateLimitConfig {
        let endpoint_key = format!("{}_{}", method, path.replace('/', "_").trim_start_matches('_'));
        self.endpoint_configs.get(&endpoint_key).unwrap_or(&self.global_config)
    }

    pub fn check_rate_limit(&self, key: &str, method: &str, path: &str) -> bool {
        self.check_rate_limit_with_test_user(key, method, path, false)
    }

    pub fn check_rate_limit_with_test_user(&self, key: &str, method: &str, path: &str, is_test_user: bool) -> bool {
        // Check if rate limiting should be bypassed for test users
        if is_test_user && self.should_skip_rate_limit_for_test_users() {
            return true;
        }

        // Check if rate limiting should be bypassed based on IP for test users
        if self.should_skip_rate_limit_for_test_user(key) {
            return true;
        }

        let config = self.get_config_for_endpoint(method, path);
        let now = Instant::now();
        let window_start = now - config.window_duration;
        
        // Create a unique key that includes the endpoint for per-endpoint limiting
        let rate_limit_key = format!("{}:{}:{}", key, method, path);
        
        // Get or create entry for this key
        let mut entry = self.requests.entry(rate_limit_key).or_insert_with(Vec::new);
        
        // Remove old entries outside the window
        entry.retain(|&timestamp| timestamp > window_start);
        
        // Check if we're within the rate limit
        if entry.len() < config.max_requests {
            entry.push(now);
            true
        } else {
            false
        }
    }

    pub fn is_test_user_by_claims(&self, claims: &Claims) -> bool {
        // Check if testing mode is enabled
        let testing_mode = env::var("TESTING_MODE")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        
        if !testing_mode {
            return false;
        }

        // Check if the user's email matches any of the test user emails
        let test_emails = [
            env::var("TEST_EMAIL").unwrap_or_default(),
            env::var("TEST_USER_1_EMAIL").unwrap_or_default(),
            env::var("TEST_USER_2_EMAIL").unwrap_or_default(),
            env::var("TEST_USER_3_EMAIL").unwrap_or_default(),
            env::var("TEST_USER_4_EMAIL").unwrap_or_default(),
            env::var("TEST_USER_5_EMAIL").unwrap_or_default(),
        ];

        test_emails.iter().any(|email| !email.is_empty() && claims.email == *email)
    }

    fn should_skip_rate_limit_for_test_users(&self) -> bool {
        let testing_mode = env::var("TESTING_MODE")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        
        let skip_rate_limits = env::var("TEST_SKIP_RATE_LIMITS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        testing_mode && skip_rate_limits
    }

    fn should_skip_rate_limit_for_test_user(&self, key: &str) -> bool {
        // Check if testing mode is enabled and skip rate limits is configured
        let testing_mode = env::var("TESTING_MODE")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        
        let skip_rate_limits = env::var("TEST_SKIP_RATE_LIMITS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        
        if !testing_mode || !skip_rate_limits {
            return false;
        }

        // Check if the key (IP address) is from a local development environment
        // This is a simplified check for development environments
        if key == "127.0.0.1" || key == "::1" || key == "localhost" {
            return true;
        }

        false
    }
    
    /// Start a background task to clean up expired entries periodically
    fn start_cleanup_task(&self) {
        let requests = self.requests.clone();
        let cleanup_interval = Duration::from_secs(300); // Clean up every 5 minutes
        
        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            loop {
                interval.tick().await;
                let now = Instant::now();
                
                // Remove entries older than 1 hour (well beyond any rate limit window)
                let cutoff = now - Duration::from_secs(3600);
                
                requests.retain(|_key, timestamps| {
                    timestamps.retain(|&timestamp| timestamp > cutoff);
                    !timestamps.is_empty()
                });
                
                debug!("Rate limiter cleanup completed, {} active keys", requests.len());
            }
        });
    }
}

// Rate limiting middleware
pub struct RateLimitMiddleware<S> {
    service: Rc<S>,
    rate_limiter: Arc<RateLimiter>,
}

impl<S> RateLimitMiddleware<S> {
    pub fn new(service: Rc<S>, rate_limiter: Arc<RateLimiter>) -> Self {
        Self { service, rate_limiter }
    }
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let rate_limiter = self.rate_limiter.clone();

        Box::pin(async move {
            // Extract IP address for rate limiting
            let client_ip = req
                .connection_info()
                .peer_addr()
                .map(|addr| addr.split(':').next().unwrap_or(addr))
                .unwrap_or("unknown")
                .to_string();

            // Extract method and path for endpoint-specific rate limiting
            let method = req.method().to_string();
            let path = req.path().to_string();

            // Check if this is a test user by looking for JWT claims
            let mut is_test_user = false;
            if let Some(auth_header) = req.headers().get("Authorization") {
                if let Ok(auth_str) = auth_header.to_str() {
                    if let Some(token) = auth_str.strip_prefix("Bearer ") {
                        if let Ok(claims) = verify_jwt(token) {
                            is_test_user = rate_limiter.is_test_user_by_claims(&claims);
                        }
                    }
                }
            }

            // Check rate limit (with test user consideration)
            if !rate_limiter.check_rate_limit_with_test_user(&client_ip, &method, &path, is_test_user) {
                debug!("Rate limit exceeded for {} {} from {}", method, path, client_ip);
                sentry::capture_message(
                    &format!("Rate limit exceeded for {} {} from {}", method, path, client_ip),
                    sentry::Level::Warning
                );
                let response = HttpResponse::TooManyRequests()
                    .json(serde_json::json!({
                        "error": "Rate limit exceeded",
                        "message": "Too many requests from this IP address",
                        "endpoint": format!("{} {}", method, path)
                    }));
                let (http_req, _) = req.into_parts();
                return Ok(ServiceResponse::new(http_req, response));
            } else {
                debug!("Rate limit check passed for {} {} from {} (test_user: {})", method, path, client_ip, is_test_user);
            }

            // Continue with the request
            let res = service.call(req).await?;
            Ok(res.map_body(|_, body| BoxBody::new(body)))
        })
    }
}

pub struct RateLimitFactory {
    rate_limiter: Arc<RateLimiter>,
}

impl RateLimitFactory {
    pub fn new(rate_limiter: Arc<RateLimiter>) -> Self {
        Self { rate_limiter }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimitMiddleware::new(Rc::new(service), self.rate_limiter.clone()))
    }
}

pub async fn jwt_middleware(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    let token = credentials.token();
    
    // Verify JWT token
    match verify_jwt(token) {
        Ok(claims) => {
            debug!("JWT token validated for user: {}", claims.sub);
            req.extensions_mut().insert(claims);
            Ok(req)
        }
        Err(_) => {
            debug!("Invalid JWT token in middleware");
            sentry::capture_message("Invalid JWT token in middleware", sentry::Level::Warning);
            Err((actix_web::error::ErrorUnauthorized("Invalid token"), req))
        }
    }
}

pub fn extract_claims(req: &actix_web::HttpRequest) -> Option<Claims> {
    req.extensions().get::<Claims>().cloned()
}

pub fn require_role(required_role: crate::models::UserRole) -> impl Fn(&Claims) -> bool {
    move |claims: &Claims| {
        match (&claims.role, &required_role) {
            (crate::models::UserRole::Principal, _) => true, // Principal can access anything
            (role, required) if std::mem::discriminant(role) == std::mem::discriminant(required) => true,
            _ => claims.is_superuser, // Superuser can access anything
        }
    }
}

pub fn require_permission(_permission: &str) -> impl Fn(&Claims) -> bool + '_ {
    move |claims: &Claims| {
        // For now, just check superuser status
        // In a full implementation, you'd check actual permissions from database
        claims.is_superuser || matches!(claims.role, crate::models::UserRole::Principal)
    }
}
