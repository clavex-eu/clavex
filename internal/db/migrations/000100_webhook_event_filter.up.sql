-- Granular webhook event subscriptions.
-- Webhooks can now subscribe to specific event subtypes (e.g. "user.login.new_device")
-- via the event_filter column.  An empty array means "all events in events[]".
-- The events[] column retains its existing meaning (top-level event categories for
-- backwards-compatible subscriptions); event_filter provides fine-grained control.
ALTER TABLE webhooks ADD COLUMN IF NOT EXISTS event_filter TEXT[] NOT NULL DEFAULT '{}';
