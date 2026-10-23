package sessions

import (
	"io"
	"sync"
)

type Session struct {
	ID     string
	UserID string
	Conn   io.Closer
}

type Set struct {
	mu   sync.Mutex
	byID map[string]*Session
	byU  map[string]map[string]*Session
}

func New() *Set {
	return &Set{byID: map[string]*Session{}, byU: map[string]map[string]*Session{}}
}

func (s *Set) Add(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[sess.ID] = sess
	if s.byU[sess.UserID] == nil {
		s.byU[sess.UserID] = map[string]*Session{}
	}
	s.byU[sess.UserID][sess.ID] = sess
}

func (s *Set) Count(userID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byU[userID])
}

func (s *Set) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.byID[id]
	if sess == nil {
		return
	}
	delete(s.byID, id)
	delete(s.byU[sess.UserID], id)
}

func (s *Set) CloseUser(userID string) {
	s.mu.Lock()
	list := make([]*Session, 0, len(s.byU[userID]))
	for _, sess := range s.byU[userID] {
		list = append(list, sess)
	}
	s.mu.Unlock()
	for _, sess := range list {
		if sess.Conn != nil {
			_ = sess.Conn.Close()
		}
		s.Remove(sess.ID)
	}
}
