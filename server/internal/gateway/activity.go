package gateway

// ActiveCount includes unattached tickets and closing sessions until audit ends.
func (b *Broker) ActiveCount() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.sessions) }
