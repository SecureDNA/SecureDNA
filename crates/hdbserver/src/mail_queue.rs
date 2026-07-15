// Copyright 2021-2026 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(dead_code)] // Used in an upcoming PR.

use thiserror::Error;

use crate::mail::Email;
use std::time::{Duration, Instant};

/// A queue of outgoing emails, all to the same recipient.
pub struct MailQueue {
    /// Base duration used in the exponential backoff formula for queue flushing.
    pub base_duration: Duration,
    /// Maximum duration between queue population and flush.
    pub max_duration: Duration,
    /// Maximum amount of queued emails.
    pub max_size: usize,
    /// Emails in the queue.
    pub queued_emails: Vec<Email>,
    /// Time when the queue was last populated (went from empty to non-empty).
    pub start_time: Option<Instant>,
    /// Time when the queue is scheduled to be flushed.
    pub flush_time: Option<Instant>,
    /// Timestamps of when emails were added to the queue (including already-flushed emails).
    pub email_timestamps: Vec<Instant>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MailAdded {
    Enqueued,
    Merged,
}

#[derive(Debug, PartialEq, Eq, Error)]
#[error("mail queue is full")]
pub struct QueueFull;

impl MailQueue {
    pub fn new(base_duration: Duration, max_duration: Duration, max_size: usize) -> Self {
        Self {
            base_duration,
            max_duration,
            max_size,
            queued_emails: vec![],
            start_time: None,
            flush_time: None,
            email_timestamps: vec![],
        }
    }

    /// Add an email to the queue. If an email with the same to_email, subject, and body already exists,
    /// append the attachments to the existing email.
    pub fn add(&mut self, email: Email) -> Result<MailAdded, QueueFull> {
        let now = Instant::now();
        let start_time = *self.start_time.get_or_insert(now);

        // Clean up old timestamps to prevent unbounded growth
        let cutoff = now - self.max_duration;
        self.email_timestamps
            .retain(|&timestamp| timestamp >= cutoff);

        if self.is_full() {
            return Err(QueueFull);
        }

        let mail_added = if let Some(previous_email) = self.queued_emails.iter_mut().find(|e| {
            e.to_email == email.to_email && e.subject == email.subject && e.body == email.body
        }) {
            previous_email.attachments.extend(email.attachments);
            MailAdded::Merged
        } else {
            self.queued_emails.push(email);
            MailAdded::Enqueued
        };

        self.email_timestamps.push(now);

        // Calculate dynamic flush delay based on emails added in last max_duration
        let emails_in_window = self.email_timestamps.len(); // Already cleaned up, so this is accurate
        let delay = {
            // Exponential backoff: delay = base_duration * 2^n
            // We subtract 1 so that we use the base duration after enqueuing the first email.
            // We don't need to cap this, because flush_time_limit will eventually be reached.
            let n = (emails_in_window as u32).saturating_sub(1);
            self.base_duration.saturating_mul(2u32.saturating_pow(n))
        };

        let backoff_end_time = now + delay;
        let flush_time_limit = start_time + self.max_duration;

        self.flush_time = Some(backoff_end_time.min(flush_time_limit));

        Ok(mail_added)
    }

    /// Flush the queue, returning all emails in the queue.
    pub fn flush(&mut self) -> Vec<Email> {
        self.start_time = None;
        self.flush_time = None;
        std::mem::take(&mut self.queued_emails)
    }

    /// Poll the queue, returning all emails in the queue if the queue should be flushed.
    pub fn poll(&mut self) -> Option<Vec<Email>> {
        self.should_flush().then(|| self.flush())
    }

    /// Check if the queue should be flushed, either because the flush time has been reached or the queue is at maximum size.
    pub fn should_flush(&self) -> bool {
        self.flush_time.is_some_and(|time| time <= Instant::now())
    }

    /// Check if the queue is full.
    pub fn is_full(&self) -> bool {
        self.queued_emails.len() >= self.max_size
    }
}

#[cfg(test)]
mod tests {
    use crate::mail::Attachment;

    use super::*;
    fn make_test_email(index: usize) -> Email {
        Email {
            from_email: "test@example.com".to_owned(),
            from_name: "Test Sender".to_owned(),
            to_email: "recipient@example.com".to_owned(),
            to_name: "Test Recipient".to_owned(),
            subject: format!("Test Subject {}", index),
            body: format!("Test Body {}", index),
            attachments: vec![],
        }
    }

    #[test]
    fn test_queue_starts_empty() {
        let queue = MailQueue::new(Duration::from_mins(5), Duration::from_hours(1), 5);
        assert_eq!(queue.queued_emails.len(), 0);
        assert!(queue.flush_time.is_none());
        assert!(!queue.should_flush());
    }

    #[test]
    fn test_queue_fills_up() {
        let mut queue = MailQueue::new(Duration::from_mins(5), Duration::from_hours(1), 5);

        // Add 5 emails (max_size)
        for i in 0..4 {
            queue.add(make_test_email(i)).unwrap();
            assert!(!queue.is_full());
        }

        queue.add(make_test_email(4)).unwrap();
        assert!(queue.is_full());
        queue.add(make_test_email(5)).unwrap_err();
    }

    #[test]
    fn test_queue_merges_emails_with_same_recipient_and_body() {
        let mut queue = MailQueue::new(Duration::from_mins(5), Duration::from_hours(1), 5);

        // Create two emails with same to_email, subject, and body but different attachments
        let email1 = Email {
            from_email: "test@example.com".to_owned(),
            from_name: "Test Sender".to_owned(),
            to_email: "recipient@example.com".to_owned(),
            to_name: "Test Recipient".to_owned(),
            subject: "Same Subject".to_owned(),
            body: "Same Body".to_owned(),
            attachments: vec![Attachment {
                content: b"file1".to_vec(),
                content_type: "text/plain".to_owned(),
                filename: "file1.txt".to_owned(),
            }],
        };

        let email2 = Email {
            from_email: "test@example.com".to_owned(),
            from_name: "Test Sender".to_owned(),
            to_email: "recipient@example.com".to_owned(),
            to_name: "Test Recipient".to_owned(),
            subject: "Same Subject".to_owned(),
            body: "Same Body".to_owned(),
            attachments: vec![Attachment {
                content: b"file2".to_vec(),
                content_type: "text/plain".to_owned(),
                filename: "file2.txt".to_owned(),
            }],
        };

        queue.add(email1).unwrap();
        queue.add(email2).unwrap();

        // Should have merged into a single email
        assert_eq!(queue.queued_emails.len(), 1);
        assert_eq!(queue.queued_emails[0].attachments.len(), 2);
    }

    #[test]
    fn test_queue_does_not_merge_emails_with_different_body() {
        let mut queue = MailQueue::new(Duration::from_mins(5), Duration::from_hours(1), 5);

        let email1 = Email {
            from_email: "test@example.com".to_owned(),
            from_name: "Test Sender".to_owned(),
            to_email: "recipient@example.com".to_owned(),
            to_name: "Test Recipient".to_owned(),
            subject: "Same Subject".to_owned(),
            body: "Body 1".to_owned(),
            attachments: vec![],
        };

        let email2 = Email {
            from_email: "test@example.com".to_owned(),
            from_name: "Test Sender".to_owned(),
            to_email: "recipient@example.com".to_owned(),
            to_name: "Test Recipient".to_owned(),
            subject: "Same Subject".to_owned(),
            body: "Body 2".to_owned(),
            attachments: vec![],
        };

        queue.add(email1).unwrap();
        queue.add(email2).unwrap();

        // Should NOT merge - different bodies
        assert_eq!(queue.queued_emails.len(), 2);
    }

    #[test]
    fn test_queue_sets_flush_time_on_add() {
        let mut queue = MailQueue::new(Duration::from_mins(5), Duration::from_hours(1), 5);

        assert!(queue.flush_time.is_none());

        queue.add(make_test_email(0)).unwrap();

        assert!(queue.flush_time.is_some());
        let first_flush_time = queue.flush_time.unwrap();

        // Adding another email should update the flush time
        std::thread::sleep(Duration::from_millis(10));
        queue.add(make_test_email(1)).unwrap();

        let second_flush_time = queue.flush_time.unwrap();
        assert!(second_flush_time >= first_flush_time);
    }

    #[test]
    fn test_queue_flush_clears_emails() {
        let mut queue = MailQueue::new(Duration::from_mins(5), Duration::from_hours(1), 5);

        queue.add(make_test_email(0)).unwrap();
        queue.add(make_test_email(1)).unwrap();

        assert_eq!(queue.queued_emails.len(), 2);

        let emails = queue.flush();
        assert_eq!(emails.len(), 2);
        assert_eq!(queue.queued_emails.len(), 0);
        assert!(queue.flush_time.is_none());
        assert!(queue.start_time.is_none());
    }

    #[test]
    fn test_queue_poll_returns_none_when_not_ready() {
        let mut queue = MailQueue::new(Duration::from_mins(5), Duration::from_hours(1), 5);

        // Add just one email (not at max_size and flush_time is in the future)
        queue.add(make_test_email(0)).unwrap();

        // Immediately poll - should return None because flush_time hasn't passed
        let result = queue.poll();
        assert!(result.is_none());
        assert_eq!(queue.queued_emails.len(), 1); // Email still in queue
    }
}
