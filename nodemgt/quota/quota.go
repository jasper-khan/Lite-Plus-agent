package quota

import "sync"

type Ledger struct {
	mu    sync.Mutex
	used  map[string]int64
	limit map[string]int64
}

func New() *Ledger {
	return &Ledger{used: map[string]int64{}, limit: map[string]int64{}}
}

func (l *Ledger) Configure(userID string, limit, used int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.limit[userID] = limit
	l.used[userID] = used
}

func (l *Ledger) Add(userID string, n int64) (used, limit int64, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	limit = l.limit[userID]
	used = l.used[userID] + n
	if limit > 0 && used > limit {
		return l.used[userID], limit, false
	}
	l.used[userID] = used
	return used, limit, true
}

func (l *Ledger) Used(userID string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used[userID]
}

func (l *Ledger) Room(userID string) int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	limit := l.limit[userID]
	if limit <= 0 {
		return -1
	}
	room := limit - l.used[userID]
	if room < 0 {
		return 0
	}
	return room
}

func (l *Ledger) Snapshot() map[string]int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]int64, len(l.used))
	for k, v := range l.used {
		out[k] = v
	}
	return out
}
