use std::collections::HashMap;

use chrono::{DateTime, TimeDelta, Utc};
use tokio::sync::Mutex;

use crate::constants;

pub struct LoginRateLimiter {
    failures: Mutex<Vec<DateTime<Utc>>>,
    window: TimeDelta,
    max_failures: usize,
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self {
            failures: Mutex::new(Vec::new()),
            window: TimeDelta::seconds(constants::RATE_LIMIT_WINDOW_SECS),
            max_failures: constants::LOGIN_MAX_FAILURES,
        }
    }

    pub async fn check_rate_limit(&self) -> Result<(), u64> {
        let mut failures = self.failures.lock().await;
        let now = Utc::now();
        let cutoff = now - self.window;

        failures.retain(|t| *t > cutoff);

        if failures.len() >= self.max_failures {
            let oldest = failures.first().unwrap();
            let retry_after = (*oldest + self.window - now).num_seconds().max(1) as u64;
            return Err(retry_after);
        }

        Ok(())
    }

    pub async fn record_failure(&self) {
        let mut failures = self.failures.lock().await;
        failures.push(Utc::now());
    }

    async fn failure_count(&self) -> usize {
        let failures = self.failures.lock().await;
        let now = Utc::now();
        let cutoff = now - self.window;
        failures.iter().filter(|t| **t > cutoff).count()
    }

    pub async fn progressive_delay(&self) {
        let count = self.failure_count().await;
        let delay = match count {
            0..=2 => 0,
            3 => 1,
            4 => 2,
            _ => 5,
        };
        if delay > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
        }
    }

    pub async fn reset(&self) {
        let mut failures = self.failures.lock().await;
        failures.clear();
    }
}

pub struct ProxyRateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_second: f64,
    last_refill: DateTime<Utc>,
}

impl TokenBucket {
    fn new(max_requests: u32, window_seconds: u64, now: DateTime<Utc>) -> Self {
        let capacity = max_requests.max(1) as f64;
        let refill_per_second = capacity / window_seconds.max(1) as f64;
        Self {
            tokens: capacity,
            capacity,
            refill_per_second,
            last_refill: now,
        }
    }

    fn reconfigure(&mut self, max_requests: u32, window_seconds: u64, now: DateTime<Utc>) {
        self.refill(now);
        self.capacity = max_requests.max(1) as f64;
        self.refill_per_second = self.capacity / window_seconds.max(1) as f64;
        if self.tokens > self.capacity {
            self.tokens = self.capacity;
        }
    }

    fn refill(&mut self, now: DateTime<Utc>) {
        let elapsed_ms = (now - self.last_refill).num_milliseconds().max(0) as f64;
        if elapsed_ms <= 0.0 {
            return;
        }
        let refill = (elapsed_ms / 1000.0) * self.refill_per_second;
        self.tokens = (self.tokens + refill).min(self.capacity);
        self.last_refill = now;
    }

    fn try_take(&mut self, now: DateTime<Utc>) -> Result<(), u64> {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Ok(());
        }

        let needed = 1.0 - self.tokens;
        let retry_after = (needed / self.refill_per_second).ceil() as u64;
        Err(retry_after.max(1))
    }
}

impl Default for ProxyRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyRateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub async fn check_and_record(&self, service: &str, max_per_minute: u32) -> Result<(), u64> {
        self.check_and_record_with_window(
            service,
            max_per_minute,
            constants::RATE_LIMIT_WINDOW_SECS as u64,
        )
        .await
    }

    pub async fn check_and_record_with_window(
        &self,
        service: &str,
        max_requests: u32,
        window_seconds: u64,
    ) -> Result<(), u64> {
        if max_requests == 0 {
            return Ok(());
        }

        let window_seconds = window_seconds.max(1);
        let mut buckets = self.buckets.lock().await;
        let now = Utc::now();
        let bucket = buckets
            .entry(service.to_string())
            .or_insert_with(|| TokenBucket::new(max_requests, window_seconds, now));
        bucket.reconfigure(max_requests, window_seconds, now);
        bucket.try_take(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn proxy_rate_limiter_allows_within_limit() {
        let limiter = ProxyRateLimiter::new();
        for _ in 0..5 {
            assert!(limiter.check_and_record("openai", 10).await.is_ok());
        }
    }

    #[tokio::test]
    async fn proxy_rate_limiter_blocks_over_limit() {
        let limiter = ProxyRateLimiter::new();
        for _ in 0..3 {
            assert!(limiter.check_and_record("openai", 3).await.is_ok());
        }
        let result = limiter.check_and_record("openai", 3).await;
        assert!(result.is_err());
        let retry_after = result.unwrap_err();
        assert!(retry_after > 0);
    }

    #[tokio::test]
    async fn proxy_rate_limiter_services_are_independent() {
        let limiter = ProxyRateLimiter::new();
        for _ in 0..3 {
            assert!(limiter.check_and_record("openai", 3).await.is_ok());
        }
        assert!(limiter.check_and_record("openai", 3).await.is_err());
        assert!(limiter.check_and_record("anthropic", 3).await.is_ok());
    }

    #[tokio::test]
    async fn proxy_rate_limiter_zero_limit_disables_check() {
        let limiter = ProxyRateLimiter::new();
        for _ in 0..100 {
            assert!(
                limiter
                    .check_and_record_with_window("custom", 0, 10)
                    .await
                    .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn proxy_rate_limiter_refills_after_wait() {
        let limiter = ProxyRateLimiter::new();
        assert!(
            limiter
                .check_and_record_with_window("custom", 1, 1)
                .await
                .is_ok()
        );
        assert!(
            limiter
                .check_and_record_with_window("custom", 1, 1)
                .await
                .is_err()
        );
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert!(
            limiter
                .check_and_record_with_window("custom", 1, 1)
                .await
                .is_ok()
        );
    }
}
