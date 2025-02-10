/*
    Copyright 2025 TII (SSRC) and the contributors
    SPDX-License-Identifier: Apache-2.0
*/
use log::{info, warn};
use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::interval;
use tokio::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use pnet::packet::ip::IpNextHeaderProtocol;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct Security {
    background_task_period: Duration,
    cancel_token: Mutex<CancellationToken>,
    rate_limiter: Mutex<RateLimiter>,
}

/// Represents a rate limiter for (src_ip, protocol, dest_port) tuples.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    enabled: bool,
    routes: HashMap<(Ipv4Addr, IpNextHeaderProtocol, u16), VecDeque<Instant>>, // Key: (src_ip, protocol, dest_port)
    max_routes: usize,
    max_requests: usize,         // Max requests per time window
    window: Duration,            // Sliding time window
    _cleanup_interval: Duration, // How often to remove stale IP
}

impl Security {
    pub fn new(rate_limiter: &RateLimiter) -> Arc<Self> {
        const BACKGROUND_TASK_PERIOD: Duration = Duration::from_millis(1000);
        let security = Arc::new(Self {
            background_task_period: BACKGROUND_TASK_PERIOD,
            cancel_token: Mutex::new(CancellationToken::default()),
            rate_limiter: Mutex::new(rate_limiter.clone()),
        });

        // Spawn the background cleanup task without moving `security`
        let security_clone = Arc::clone(&security);
        tokio::spawn(async move { security_clone.background_task().await });
        security
    }
    /// Background task to clean up old keys (inactive IPs)
    async fn background_task(self: Arc<Self>) {
        let mut interval = interval(self.background_task_period);
        let cancel_token = &self.cancel_token.lock().await;
        let mut rate_limiter_cnt = 0;
        loop {
            tokio::select! {
                      // Check the cancellation token
                      _ = cancel_token.cancelled() => {
                        // Token was cancelled, clean up and exit task
                        warn!("Cancellation token triggered, shutting down security background task");
                        break;
                    }
                _ = async {
                    interval.tick().await;
                    let mut rate_limiter_lock = self.rate_limiter.lock().await;
                    rate_limiter_cnt = (rate_limiter_cnt + 1) % 10;

                    if rate_limiter_cnt ==0{
                        rate_limiter_lock.cleanup_old_requests();

                    }
                }=> {}
            }
        }
    }

    pub async fn is_packet_secure(
        self: Arc<Self>,
        src_ip: Ipv4Addr,
        protocol: IpNextHeaderProtocol,
        src_port: u16,
        dest_port: u16,
    ) -> bool {
        if dest_port == 0 || src_port == 0 {
            return false;
        }

        let mut rate_limiter_lock = self.rate_limiter.lock().await;

        if !rate_limiter_lock.enabled {
            return true;
        }

        rate_limiter_lock.is_allowed(src_ip, protocol, dest_port)
    }

    pub async fn set_rate_limiter(self: Arc<Self>, enabled: bool) {
        let mut rate_limiter_lock = self.rate_limiter.lock().await;

        rate_limiter_lock.enabled = enabled;
    }
    pub async fn set_cancel_token(self: Arc<Self>, token: CancellationToken) {
        let mut cancel_token = self.cancel_token.lock().await;
        *cancel_token = token;
    }
}

impl RateLimiter {
    /// Creates a new rate limiter with given limits.
    pub fn new(
        enabled: bool,
        max_requests: usize,
        window: Duration,
        _cleanup_interval: Duration,
    ) -> Self {
        Self {
            enabled,
            routes: HashMap::new(),
            max_routes: 50,
            max_requests: if max_requests > 1 {
                max_requests - 1
            } else {
                max_requests
            },
            window,
            _cleanup_interval,
        }
    }

    /// Checks if a request from `(src_ip, protocol, dest_port)` is allowed.
    fn is_allowed(
        &mut self,
        src_ip: Ipv4Addr,
        protocol: IpNextHeaderProtocol,
        dest_port: u16,
    ) -> bool {
        let now = Instant::now();
        let key = (src_ip, protocol, dest_port);

        // Prevent memory explosion
        if self.routes.len() >= self.max_routes && !self.routes.contains_key(&key) {
            return false;
        }
        // Get or insert key with an empty vector
        let timestamps = self.routes.entry(key).or_default();

        // Remove expired timestamps (only keep recent ones within the window)
        timestamps.retain(|&t| now.duration_since(t) <= self.window);

        // Check if within rate limit
        if timestamps.len() < self.max_requests {
            timestamps.push_back(now);
            true
        } else {
            false
        }
    }

    /// Cleanup function to remove expired requests
    fn cleanup_old_requests(&mut self) {
        let now = Instant::now();

        self.routes.retain(|_, timestamps| {
            timestamps.retain(|&t| now.duration_since(t) <= self.window);
            !timestamps.is_empty()
        });

        info!("Cleanup done: Active routes: {}", self.routes.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration;

    #[test]
    fn test_cleanup_old_requests() {
        let mut rate_limiter = RateLimiter::new(
            true,
            5,
            Duration::from_millis(100),
            Duration::from_millis(50),
        );

        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let protocol = IpNextHeaderProtocol::new(6); // TCP
        let dest_port = 8080;

        let key = (src_ip, protocol, dest_port);

        // Add some timestamps (some should expire)
        let now = Instant::now();
        rate_limiter.routes.insert(
            key,
            VecDeque::from(vec![
                now - Duration::from_millis(200), // Expired
                now - Duration::from_millis(50),  // Valid
            ]),
        );

        // Ensure the entry exists before cleanup
        assert_eq!(rate_limiter.routes.get(&key).unwrap().len(), 2);

        // Call cleanup function (log_count doesn't affect functionality)
        rate_limiter.cleanup_old_requests();

        // Only 1 valid timestamp should remain
        assert_eq!(rate_limiter.routes.get(&key).unwrap().len(), 1);
    }
}
