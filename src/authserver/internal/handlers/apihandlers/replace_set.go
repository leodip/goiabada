package apihandlers

// replaceSet says how to make the stored rows exactly the wanted keys: the row ids to delete, every
// row whose key is not wanted and every row after the first for a key that is, and the keys to
// insert, every wanted key no row carries. Wanted keys are taken in order, first occurrence.
// Deterministic: remove is in stored order and insert in wanted order.
//
// It is the one plan every save that replaces a whole list applies inside its transaction. Deleting
// every extra copy of a key is what repairs a list an earlier writer stored twice, which dynamic
// registration did for a repeated redirect URI and the user permission save did for a repeated id:
// keyed by value, those saves held one row id per key, so removing the value deleted one copy and
// left the other live (#428, #406).
func replaceSet[R any, K comparable](stored []R, key func(R) K, id func(R) int64, wanted []K) (insert []K, remove []int64) {
	wantedSet := make(map[K]struct{}, len(wanted))
	for _, k := range wanted {
		wantedSet[k] = struct{}{}
	}

	kept := make(map[K]struct{}, len(stored))
	for _, row := range stored {
		k := key(row)
		if _, isWanted := wantedSet[k]; !isWanted {
			remove = append(remove, id(row))
			continue
		}
		if _, already := kept[k]; already {
			remove = append(remove, id(row))
			continue
		}
		kept[k] = struct{}{}
	}

	for _, k := range wanted {
		if _, present := kept[k]; present {
			continue
		}
		kept[k] = struct{}{}
		insert = append(insert, k)
	}
	return insert, remove
}

// revokedKeys is the keys replaceSet's plan takes away outright: every stored key that is not
// wanted, once however many rows carry it, in stored order. A save that audits per item emits one
// removal event per key here after its commit. The extra copies of a wanted key that replaceSet also
// deletes are not in it: that key is still granted, so deleting its copies is a repair and not a
// revocation, and an event for it would tell an auditor a grant was withdrawn that was not (#428).
func revokedKeys[R any, K comparable](stored []R, key func(R) K, wanted []K) []K {
	wantedSet := make(map[K]struct{}, len(wanted))
	for _, k := range wanted {
		wantedSet[k] = struct{}{}
	}
	var revoked []K
	seen := make(map[K]struct{}, len(stored))
	for _, row := range stored {
		k := key(row)
		if _, isWanted := wantedSet[k]; isWanted {
			continue
		}
		if _, already := seen[k]; already {
			continue
		}
		seen[k] = struct{}{}
		revoked = append(revoked, k)
	}
	return revoked
}

// firstOccurrences is keys with each repeat dropped, first occurrence kept, in order. A save
// deduplicates its request with it before validating, so each value is checked once and the per-item
// audit events name each value once. Never nil, so an empty request stays an empty list (#406, #428).
func firstOccurrences[K comparable](keys []K) []K {
	out := make([]K, 0, len(keys))
	seen := make(map[K]struct{}, len(keys))
	for _, k := range keys {
		if _, already := seen[k]; already {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

// sameSet reports whether the stored rows carry exactly the keys the caller loaded, order and
// repeats ignored. A save that replaces a list calls it on the rows it read inside its transaction,
// before planning, and refuses with errListChanged when it is false: the caller's page or script
// was built from a list another save has since changed, and applying its whole list would silently
// undo that change. RFC 9110 section 15.5.10 names this conflict as a use of 409 (#428).
func sameSet[R any, K comparable](stored []R, key func(R) K, expected []K) bool {
	storedSet := make(map[K]struct{}, len(stored))
	for _, row := range stored {
		storedSet[key(row)] = struct{}{}
	}
	expectedSet := make(map[K]struct{}, len(expected))
	for _, k := range expected {
		if _, ok := storedSet[k]; !ok {
			return false
		}
		expectedSet[k] = struct{}{}
	}
	return len(expectedSet) == len(storedSet)
}
