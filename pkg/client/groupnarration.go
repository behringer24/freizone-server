package client

import (
	"fmt"

	"github.com/behringer24/freizone-server/pkg/group"
)

// Saying what changed in a group, in words.
//
// A membership change is not a message and is never sent anywhere -- these
// lines are written locally by whoever folded the facts, on every device
// independently. They read identically on all of them because they are derived
// from the same before/after fold rather than from whoever happened to make the
// change.

// memberLabel is how a member is named in a line: the same leading characters a
// transcript labels a bubble's author with, so the two read as the same person.
//
// Frozen into the stored line rather than resolved when it is displayed. A line
// is a record of a moment, and re-labelling it later with a name somebody has
// since changed would quietly rewrite history.
func memberLabel(accountID string) string {
	if len(accountID) > 5 {
		return accountID[:5]
	}
	return accountID
}

// groupStateChangeLines is the narration for the change from before to after.
//
// A nil before means this device held no facts about the group at all -- an
// invitation arriving, or a group reappearing after being forgotten locally.
// There is then no change to narrate: everything is new, and a transcript that
// opens with a replay of the whole membership history says nothing about what
// just happened.
//
// batch is used only to tell "left" from "was removed". Safe even when it
// carries facts already known -- a redelivered snapshot -- because a line is
// only ever produced for a difference the fold actually made.
func groupStateChangeLines(before, after *group.Resolved, myAccountID string, batch []*group.Event) []string {
	if before == nil || before.GroupID == "" || after == nil {
		return nil
	}

	wasThere := map[string]group.Member{}
	for _, m := range before.Members {
		wasThere[m.AccountID] = m
	}
	nowThere := map[string]group.Member{}
	for _, m := range after.Members {
		nowThere[m.AccountID] = m
	}

	// Second person for this account, third for everyone else -- with the verb
	// forms that follow, so a line reads properly either way ("You were
	// invited." / "q2xjx was invited.").
	who := func(id string) string {
		if id == myAccountID {
			return "You"
		}
		return memberLabel(id)
	}
	was := func(id string) string { return pick(id == myAccountID, "were", "was") }
	has := func(id string) string { return pick(id == myAccountID, "have", "has") }
	isNow := func(id string) string { return pick(id == myAccountID, "are", "is") }

	var lines []string

	// Gone. Which way it happened is in the batch, when it says so
	// unambiguously. In member order rather than map order, so two devices
	// folding the same facts write the same transcript.
	for _, m := range before.Members {
		id := m.AccountID
		if _, still := nowThere[id]; still {
			continue
		}
		left := batchHas(batch, group.EventLeave, id)
		removed := batchHas(batch, group.EventMemberRemove, id)
		switch {
		case left && !removed:
			lines = append(lines, fmt.Sprintf("%s left the group.", who(id)))
		case removed && !left:
			lines = append(lines, fmt.Sprintf("%s %s removed from the group.", who(id), was(id)))
		default:
			// Both, or neither -- say only what is certainly true.
			lines = append(lines, fmt.Sprintf("%s %s no longer a member.", who(id), isNow(id)))
		}
	}

	// Arrived, and accepted. An invitation and its acceptance are two facts and
	// read as two lines, which is what makes an outstanding invitation visible.
	for _, now := range after.Members {
		id := now.AccountID
		prior, existed := wasThere[id]
		if !existed {
			lines = append(lines, fmt.Sprintf("%s %s invited.", who(id), was(id)))
			if now.Joined {
				lines = append(lines, fmt.Sprintf("%s joined the group.", who(id)))
			}
			continue
		}
		if !prior.Joined && now.Joined {
			lines = append(lines, fmt.Sprintf("%s joined the group.", who(id)))
		}
		if prior.Role != now.Role {
			lines = append(lines, roleLine(who(id), has(id), isNow(id), prior.Role, now.Role))
		}
	}

	if before.Name != after.Name {
		if after.Name == "" {
			lines = append(lines, "The group name was removed.")
		} else {
			lines = append(lines, fmt.Sprintf("The group is now called %q.", after.Name))
		}
	}
	if before.Topic != after.Topic {
		if after.Topic == "" {
			lines = append(lines, "The topic was removed.")
		} else {
			lines = append(lines, fmt.Sprintf("The topic is now %q.", after.Topic))
		}
	}
	if !before.Dissolved && after.Dissolved {
		lines = append(lines, "The group was dissolved.")
	}
	return lines
}

// roleLine words a role change by direction rather than by which event carried
// it: the fold may have arrived at the same place through a grant, a
// revocation, or the re-admission of an earlier one.
func roleLine(who, has, isNow string, from, to group.Role) string {
	if to == group.RoleMember {
		return fmt.Sprintf("%s %s no special role any more.", who, has)
	}
	if to > from {
		return fmt.Sprintf("%s %s now %s.", who, isNow, to)
	}
	return fmt.Sprintf("%s %s now %s (was %s).", who, isNow, to, from)
}

func batchHas(batch []*group.Event, t group.EventType, subject string) bool {
	for _, e := range batch {
		if e != nil && e.Type == t && e.Subject == subject {
			return true
		}
	}
	return false
}

func pick(cond bool, yes, no string) string {
	if cond {
		return yes
	}
	return no
}
