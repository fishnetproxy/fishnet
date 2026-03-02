use chrono::{DateTime, Timelike, Utc};
use std::collections::{HashMap, HashSet, VecDeque};

const VOLUME_LOOKBACK_MINUTES: usize = 30;
const VOLUME_MIN_BASELINE_SAMPLES: usize = 10;
const VOLUME_MULTIPLIER: f64 = 3.0;
const VOLUME_MIN_THRESHOLD: u32 = 10;
const TIME_ANOMALY_MIN_REQUESTS: u64 = 30;
const MAX_SEEN_ACTIONS_PER_SERVICE: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnomalyKind {
    NewEndpoint,
    VolumeSpike,
    TimeAnomaly,
}

#[derive(Debug, Clone)]
pub struct AnomalyEvent {
    pub kind: AnomalyKind,
    pub detail: String,
}

#[derive(Debug, Default)]
pub struct AnomalyTracker {
    services: HashMap<String, ServiceAnomalyState>,
}

#[derive(Debug, Default)]
struct ServiceAnomalyState {
    seen_actions: HashSet<String>,
    minute_epoch: Option<i64>,
    minute_count: u32,
    recent_minute_counts: VecDeque<u32>,
    hour_counts: [u32; 24],
    total_requests: u64,
    last_volume_alert_minute: Option<i64>,
    last_time_alert_hour: Option<i64>,
}

impl AnomalyTracker {
    pub fn observe(
        &mut self,
        service: &str,
        action: &str,
        now: DateTime<Utc>,
    ) -> Vec<AnomalyEvent> {
        let service = service.trim();
        let action = action.trim();
        if service.is_empty() || action.is_empty() {
            return Vec::new();
        }

        let current_minute = now.timestamp().div_euclid(60);
        let hour_slot = now.hour() as usize;
        let hour_key = current_minute.div_euclid(60);
        let state = self.services.entry(service.to_string()).or_default();

        match state.minute_epoch {
            None => state.minute_epoch = Some(current_minute),
            Some(previous_minute) if current_minute > previous_minute => {
                Self::push_minute_sample(state, state.minute_count);
                let gap = (current_minute - previous_minute - 1)
                    .clamp(0, VOLUME_LOOKBACK_MINUTES as i64) as usize;
                for _ in 0..gap {
                    Self::push_minute_sample(state, 0);
                }
                state.minute_epoch = Some(current_minute);
                state.minute_count = 0;
            }
            _ => {}
        }

        let mut events = Vec::new();
        if !state.seen_actions.contains(action)
            && state.seen_actions.len() < MAX_SEEN_ACTIONS_PER_SERVICE
        {
            events.push(AnomalyEvent {
                kind: AnomalyKind::NewEndpoint,
                detail: format!("first observed endpoint for service {service}: {action}"),
            });
        }

        let (recent_avg, threshold) =
            if state.recent_minute_counts.len() >= VOLUME_MIN_BASELINE_SAMPLES {
                let sample_count = state
                    .recent_minute_counts
                    .len()
                    .min(VOLUME_LOOKBACK_MINUTES);
                let recent_sum: u64 = state
                    .recent_minute_counts
                    .iter()
                    .rev()
                    .take(sample_count)
                    .map(|count| u64::from(*count))
                    .sum();
                let avg = recent_sum as f64 / sample_count as f64;
                let dynamic_threshold =
                    ((avg * VOLUME_MULTIPLIER).ceil() as u32).max(VOLUME_MIN_THRESHOLD);
                (avg, dynamic_threshold)
            } else {
                (0.0, VOLUME_MIN_THRESHOLD)
            };
        let projected_this_minute = state.minute_count.saturating_add(1);

        if projected_this_minute >= threshold
            && state.last_volume_alert_minute != Some(current_minute)
        {
            events.push(AnomalyEvent {
                kind: AnomalyKind::VolumeSpike,
                detail: format!(
                    "projected {projected_this_minute} req/min exceeds threshold {threshold} (avg {recent_avg:.2} req/min)"
                ),
            });
            state.last_volume_alert_minute = Some(current_minute);
        }

        if state.total_requests >= TIME_ANOMALY_MIN_REQUESTS
            && state.hour_counts[hour_slot] == 0
            && state.last_time_alert_hour != Some(hour_key)
        {
            events.push(AnomalyEvent {
                kind: AnomalyKind::TimeAnomaly,
                detail: format!(
                    "first request observed at hour {:02}:00 UTC after {} prior requests",
                    hour_slot, state.total_requests
                ),
            });
            state.last_time_alert_hour = Some(hour_key);
        }

        if state.seen_actions.len() < MAX_SEEN_ACTIONS_PER_SERVICE {
            state.seen_actions.insert(action.to_string());
        }
        state.minute_count = state.minute_count.saturating_add(1);
        state.hour_counts[hour_slot] = state.hour_counts[hour_slot].saturating_add(1);
        state.total_requests = state.total_requests.saturating_add(1);

        events
    }

    fn push_minute_sample(state: &mut ServiceAnomalyState, count: u32) {
        state.recent_minute_counts.push_back(count);
        while state.recent_minute_counts.len() > VOLUME_LOOKBACK_MINUTES {
            let _ = state.recent_minute_counts.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_kind(events: &[AnomalyEvent], kind: AnomalyKind) -> bool {
        events.iter().any(|event| event.kind == kind)
    }

    #[test]
    fn emits_new_endpoint_event_once_per_endpoint() {
        let mut tracker = AnomalyTracker::default();
        let now = chrono::DateTime::parse_from_rfc3339("2026-02-26T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let first = tracker.observe("openai", "POST /v1/chat/completions", now);
        assert!(has_kind(&first, AnomalyKind::NewEndpoint));

        let second = tracker.observe("openai", "POST /v1/chat/completions", now);
        assert!(!has_kind(&second, AnomalyKind::NewEndpoint));
    }

    #[test]
    fn emits_volume_spike_event_when_minute_rate_jumps() {
        let mut tracker = AnomalyTracker::default();
        let base = chrono::DateTime::parse_from_rfc3339("2026-02-26T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        for minute in 0..12 {
            let ts = base + chrono::Duration::minutes(i64::from(minute));
            tracker.observe("binance", "POST /api/v3/order", ts);
            tracker.observe("binance", "POST /api/v3/order", ts);
        }

        let spike_minute = base + chrono::Duration::minutes(12);
        let mut saw_spike = false;
        for _ in 0..12 {
            let events = tracker.observe("binance", "POST /api/v3/order", spike_minute);
            if has_kind(&events, AnomalyKind::VolumeSpike) {
                saw_spike = true;
            }
        }
        assert!(saw_spike);
    }

    #[test]
    fn emits_time_anomaly_when_new_hour_slot_is_seen_after_history() {
        let mut tracker = AnomalyTracker::default();
        let base = chrono::DateTime::parse_from_rfc3339("2026-02-26T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        for minute in 0..35 {
            let ts = base + chrono::Duration::minutes(i64::from(minute));
            tracker.observe("custom.github", "GET /repos", ts);
        }

        let next_hour = chrono::DateTime::parse_from_rfc3339("2026-02-26T10:01:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let events = tracker.observe("custom.github", "GET /repos", next_hour);
        assert!(has_kind(&events, AnomalyKind::TimeAnomaly));
    }
}
