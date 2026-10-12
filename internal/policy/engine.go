package policy

import (
	"sync"

	"github.com/anmaksy/ab-win/internal/domain"
)

// Reasons shown to users by `why` and the query log.
const (
	ReasonUserAllow    = "your allowlist"
	ReasonUserBlock    = "your blocklist"
	ReasonBuiltinAllow = "built-in allowlist"
)

// Decision is the result of checking a name.
type Decision struct {
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason,omitempty"`  // list name or one of the Reason* constants
	Matched string `json:"matched,omitempty"` // the rule that matched (name or a parent)
}

// RuleSet is a set of domains that also matches subdomains, plus exact-only entries.
type RuleSet struct {
	Suffix map[string]bool
	Exact  map[string]bool
}

func NewRuleSet() RuleSet {
	return RuleSet{Suffix: map[string]bool{}, Exact: map[string]bool{}}
}

// Match returns the matching rule for name.
func (r RuleSet) Match(name string) (string, bool) {
	if r.Exact[name] {
		return name, true
	}
	for d := name; d != ""; d = domain.Parent(d) {
		if r.Suffix[d] {
			return d, true
		}
	}
	return "", false
}

// Engine combines user rules, the built-in allowlist and compiled lists.
// Precedence: your allowlist > your blocklist > built-in allowlist > lists.
// Explicit user actions always win over anything shipped by default.
type Engine struct {
	mu           sync.RWMutex
	snap         *Snapshot
	userAllow    RuleSet
	userBlock    RuleSet
	builtinAllow RuleSet
}

func NewEngine() *Engine {
	return &Engine{userAllow: NewRuleSet(), userBlock: NewRuleSet(), builtinAllow: NewRuleSet()}
}

// Ready reports whether a compiled snapshot is loaded. Until then queries are
// forwarded unfiltered so our own startup never blocks the network.
func (e *Engine) Ready() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.snap != nil
}

func (e *Engine) SetSnapshot(s *Snapshot) {
	e.mu.Lock()
	e.snap = s
	e.mu.Unlock()
}

func (e *Engine) Snapshot() *Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.snap
}

func (e *Engine) SetUserRules(allow, block RuleSet) {
	e.mu.Lock()
	e.userAllow, e.userBlock = allow, block
	e.mu.Unlock()
}

func (e *Engine) SetBuiltinAllow(r RuleSet) {
	e.mu.Lock()
	e.builtinAllow = r
	e.mu.Unlock()
}

// Decide checks a queried name.
func (e *Engine) Decide(name string) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if m, ok := e.userAllow.Match(name); ok {
		return Decision{Reason: ReasonUserAllow, Matched: m}
	}
	if m, ok := e.userBlock.Match(name); ok {
		return Decision{Blocked: true, Reason: ReasonUserBlock, Matched: m}
	}
	if m, ok := e.builtinAllow.Match(name); ok {
		return Decision{Reason: ReasonBuiltinAllow, Matched: m}
	}
	if list, m, ok := e.snap.Lookup(name); ok {
		return Decision{Blocked: true, Reason: list, Matched: m}
	}
	return Decision{}
}

// UserAllowed reports whether the user explicitly allowed name, which also
// skips CNAME un-cloaking for it.
func (e *Engine) UserAllowed(name string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.userAllow.Match(name)
	return ok
}
