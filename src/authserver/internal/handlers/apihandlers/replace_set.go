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
