package desktop

func (b *Broker) ActiveCount() int { b.mu.Lock(); defer b.mu.Unlock(); return len(b.live) + b.pending }
