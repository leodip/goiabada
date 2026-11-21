package record

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Tests for ACRLevel.Priority()
// =============================================================================

func TestACRLevel_Priority(t *testing.T) {
	t.Run("All known ACR levels have correct priority ordering", func(t *testing.T) {
		// Verify exact priority values
		assert.Equal(t, 1, ACRLevel1.Priority(), "ACRLevel1 should have priority 1")
		assert.Equal(t, 2, ACRLevel2Optional.Priority(), "ACRLevel2Optional should have priority 2")
		assert.Equal(t, 3, ACRLevel2Mandatory.Priority(), "ACRLevel2Mandatory should have priority 3")

		// Verify ordering relationships
		assert.Less(t, ACRLevel1.Priority(), ACRLevel2Optional.Priority(),
			"level1 priority should be less than level2_optional priority")
		assert.Less(t, ACRLevel2Optional.Priority(), ACRLevel2Mandatory.Priority(),
			"level2_optional priority should be less than level2_mandatory priority")
		assert.Less(t, ACRLevel1.Priority(), ACRLevel2Mandatory.Priority(),
			"level1 priority should be less than level2_mandatory priority")
	})

	t.Run("Unknown ACR level returns 0", func(t *testing.T) {
		testCases := []struct {
			name     string
			acrLevel ACRLevel
		}{
			{"arbitrary unknown string", ACRLevel("unknown:acr:level")},
			{"empty string", ACRLevel("")},
			{"whitespace only", ACRLevel("   ")},
			{"similar but wrong format", ACRLevel("urn:goiabada:level3")},
			{"partial match", ACRLevel("level1")},
			{"case sensitive check", ACRLevel("urn:goiabada:LEVEL1")},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				assert.Equal(t, 0, tc.acrLevel.Priority(),
					"Unknown ACR '%s' should have priority 0", tc.acrLevel)
			})
		}
	})
}

// =============================================================================
// Tests for ACRLevel.IsHigherThan() - Exhaustive 3x3 matrix
// =============================================================================

func TestACRLevel_IsHigherThan_ExhaustiveMatrix(t *testing.T) {
	// Define all ACR levels for exhaustive testing
	allLevels := []ACRLevel{ACRLevel1, ACRLevel2Optional, ACRLevel2Mandatory}

	// Expected results for IsHigherThan(row, col) where row.IsHigherThan(col)
	// Matrix[i][j] = true if allLevels[i].IsHigherThan(allLevels[j])
	//
	//                    col: level1  level2_opt  level2_mand
	// row: level1              false      false        false
	// row: level2_optional      true      false        false
	// row: level2_mandatory     true       true        false
	expectedMatrix := [][]bool{
		{false, false, false}, // level1 is not higher than any
		{true, false, false},  // level2_optional is higher than level1 only
		{true, true, false},   // level2_mandatory is higher than level1 and level2_optional
	}

	for i, rowLevel := range allLevels {
		for j, colLevel := range allLevels {
			expected := expectedMatrix[i][j]
			t.Run(rowLevel.String()+"_vs_"+colLevel.String(), func(t *testing.T) {
				result := rowLevel.IsHigherThan(colLevel)
				assert.Equal(t, expected, result,
					"%s.IsHigherThan(%s) should be %v", rowLevel, colLevel, expected)
			})
		}
	}
}

func TestACRLevel_IsHigherThan_UnknownACR(t *testing.T) {
	unknown := ACRLevel("unknown")
	empty := ACRLevel("")

	t.Run("unknown ACR vs all known ACRs", func(t *testing.T) {
		// Unknown (priority 0) is never higher than known levels (priority >= 1)
		assert.False(t, unknown.IsHigherThan(ACRLevel1))
		assert.False(t, unknown.IsHigherThan(ACRLevel2Optional))
		assert.False(t, unknown.IsHigherThan(ACRLevel2Mandatory))
	})

	t.Run("all known ACRs vs unknown ACR", func(t *testing.T) {
		// Known levels (priority >= 1) are always higher than unknown (priority 0)
		assert.True(t, ACRLevel1.IsHigherThan(unknown))
		assert.True(t, ACRLevel2Optional.IsHigherThan(unknown))
		assert.True(t, ACRLevel2Mandatory.IsHigherThan(unknown))
	})

	t.Run("empty ACR vs all known ACRs", func(t *testing.T) {
		assert.False(t, empty.IsHigherThan(ACRLevel1))
		assert.False(t, empty.IsHigherThan(ACRLevel2Optional))
		assert.False(t, empty.IsHigherThan(ACRLevel2Mandatory))
	})

	t.Run("all known ACRs vs empty ACR", func(t *testing.T) {
		assert.True(t, ACRLevel1.IsHigherThan(empty))
		assert.True(t, ACRLevel2Optional.IsHigherThan(empty))
		assert.True(t, ACRLevel2Mandatory.IsHigherThan(empty))
	})

	t.Run("unknown vs unknown", func(t *testing.T) {
		// Both have priority 0, so neither is higher
		assert.False(t, unknown.IsHigherThan(unknown))
		assert.False(t, empty.IsHigherThan(empty))
		assert.False(t, unknown.IsHigherThan(empty))
		assert.False(t, empty.IsHigherThan(unknown))
	})
}

// =============================================================================
// Tests for ACRMax() - Exhaustive 3x3 matrix
// =============================================================================

func TestACRMax_ExhaustiveMatrix(t *testing.T) {
	allLevels := []ACRLevel{ACRLevel1, ACRLevel2Optional, ACRLevel2Mandatory}

	// Expected results for ACRMax(row, col)
	// The result should always be the higher of the two
	//
	//                    col: level1       level2_opt       level2_mand
	// row: level1              level1      level2_opt       level2_mand
	// row: level2_optional     level2_opt  level2_opt       level2_mand
	// row: level2_mandatory    level2_mand level2_mand      level2_mand
	expectedMatrix := [][]ACRLevel{
		{ACRLevel1, ACRLevel2Optional, ACRLevel2Mandatory},
		{ACRLevel2Optional, ACRLevel2Optional, ACRLevel2Mandatory},
		{ACRLevel2Mandatory, ACRLevel2Mandatory, ACRLevel2Mandatory},
	}

	for i, rowLevel := range allLevels {
		for j, colLevel := range allLevels {
			expected := expectedMatrix[i][j]
			t.Run(rowLevel.String()+"_and_"+colLevel.String(), func(t *testing.T) {
				result := ACRMax(rowLevel, colLevel)
				assert.Equal(t, expected, result,
					"ACRMax(%s, %s) should be %s", rowLevel, colLevel, expected)
			})
		}
	}
}

func TestACRMax_Commutativity(t *testing.T) {
	// ACRMax should be commutative: ACRMax(a, b) == ACRMax(b, a)
	allLevels := []ACRLevel{ACRLevel1, ACRLevel2Optional, ACRLevel2Mandatory}

	for _, a := range allLevels {
		for _, b := range allLevels {
			t.Run(a.String()+"_commutes_with_"+b.String(), func(t *testing.T) {
				assert.Equal(t, ACRMax(a, b), ACRMax(b, a),
					"ACRMax should be commutative: ACRMax(%s, %s) == ACRMax(%s, %s)",
					a, b, b, a)
			})
		}
	}
}

func TestACRMax_UnknownACR(t *testing.T) {
	unknown := ACRLevel("unknown")
	empty := ACRLevel("")

	t.Run("max of known and unknown returns known", func(t *testing.T) {
		// When one is known (priority > 0) and one is unknown (priority 0),
		// the known one should be returned
		assert.Equal(t, ACRLevel1, ACRMax(ACRLevel1, unknown))
		assert.Equal(t, ACRLevel1, ACRMax(unknown, ACRLevel1))

		assert.Equal(t, ACRLevel2Optional, ACRMax(ACRLevel2Optional, unknown))
		assert.Equal(t, ACRLevel2Optional, ACRMax(unknown, ACRLevel2Optional))

		assert.Equal(t, ACRLevel2Mandatory, ACRMax(ACRLevel2Mandatory, unknown))
		assert.Equal(t, ACRLevel2Mandatory, ACRMax(unknown, ACRLevel2Mandatory))
	})

	t.Run("max of known and empty returns known", func(t *testing.T) {
		assert.Equal(t, ACRLevel1, ACRMax(ACRLevel1, empty))
		assert.Equal(t, ACRLevel1, ACRMax(empty, ACRLevel1))

		assert.Equal(t, ACRLevel2Optional, ACRMax(ACRLevel2Optional, empty))
		assert.Equal(t, ACRLevel2Optional, ACRMax(empty, ACRLevel2Optional))

		assert.Equal(t, ACRLevel2Mandatory, ACRMax(ACRLevel2Mandatory, empty))
		assert.Equal(t, ACRLevel2Mandatory, ACRMax(empty, ACRLevel2Mandatory))
	})

	t.Run("max of two unknowns returns first argument", func(t *testing.T) {
		// When both have priority 0, ACRMax returns first argument (a >= b is true when both are 0)
		unknown1 := ACRLevel("unknown1")
		unknown2 := ACRLevel("unknown2")

		assert.Equal(t, unknown1, ACRMax(unknown1, unknown2))
		assert.Equal(t, unknown2, ACRMax(unknown2, unknown1))
		assert.Equal(t, unknown, ACRMax(unknown, empty))
		assert.Equal(t, empty, ACRMax(empty, unknown))
	})
}

// =============================================================================
// Tests for ACRLevelFromString()
// =============================================================================

func TestACRLevelFromString(t *testing.T) {
	t.Run("Valid ACR strings return correct levels", func(t *testing.T) {
		testCases := []struct {
			input    string
			expected ACRLevel
		}{
			{"urn:goiabada:level1", ACRLevel1},
			{"urn:goiabada:level2_optional", ACRLevel2Optional},
			{"urn:goiabada:level2_mandatory", ACRLevel2Mandatory},
		}

		for _, tc := range testCases {
			t.Run(tc.input, func(t *testing.T) {
				level, err := ACRLevelFromString(tc.input)
				require.NoError(t, err)
				assert.Equal(t, tc.expected, level)
			})
		}
	})

	t.Run("Invalid ACR strings return error", func(t *testing.T) {
		testCases := []struct {
			name  string
			input string
		}{
			{"empty string", ""},
			{"arbitrary string", "invalid"},
			{"partial match - missing prefix", "level1"},
			{"partial match - wrong prefix", "urn:other:level1"},
			{"case sensitive - uppercase", "URN:GOIABADA:LEVEL1"},
			{"case sensitive - mixed", "urn:goiabada:Level1"},
			{"typo in level", "urn:goiabada:levle1"},
			{"extra whitespace", " urn:goiabada:level1"},
			{"trailing whitespace", "urn:goiabada:level1 "},
			{"non-existent level", "urn:goiabada:level3"},
			{"level0", "urn:goiabada:level0"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := ACRLevelFromString(tc.input)
				require.Error(t, err)
				assert.Contains(t, err.Error(), "invalid ACR level")
			})
		}
	})
}

// =============================================================================
// Tests for ACRLevel.String()
// =============================================================================

func TestACRLevel_String(t *testing.T) {
	t.Run("All known ACR levels return correct strings", func(t *testing.T) {
		assert.Equal(t, "urn:goiabada:level1", ACRLevel1.String())
		assert.Equal(t, "urn:goiabada:level2_optional", ACRLevel2Optional.String())
		assert.Equal(t, "urn:goiabada:level2_mandatory", ACRLevel2Mandatory.String())
	})

	t.Run("String and ACRLevelFromString are inverse operations", func(t *testing.T) {
		allLevels := []ACRLevel{ACRLevel1, ACRLevel2Optional, ACRLevel2Mandatory}

		for _, level := range allLevels {
			t.Run(level.String(), func(t *testing.T) {
				// Convert to string and back
				str := level.String()
				parsed, err := ACRLevelFromString(str)
				require.NoError(t, err)
				assert.Equal(t, level, parsed)
			})
		}
	})

	// The complement of the totality the six integer enums gained in #385: ACRLevel is
	// string-backed, so there is no range to be outside of, and an unrecognized value has to
	// survive rather than collapse to "". OIDC Core defines acr as a case-sensitive string whose
	// meaning can be deployment-specific, so discarding one would change what a token carries for
	// a value this server simply does not rank. Priority answering 0 is what keeps comparison safe
	// without throwing the value away, which the unknown-ACR cases above already pin.
	t.Run("An unrecognized ACR value survives String verbatim", func(t *testing.T) {
		testCases := []string{
			"urn:goiabada:level3",
			"urn:example:loa:substantial",
			"urn:goiabada:LEVEL1",
			"level1",
			"   ",
			"",
		}

		for _, raw := range testCases {
			t.Run(raw, func(t *testing.T) {
				assert.Equal(t, raw, ACRLevel(raw).String(),
					"String must not collapse an acr value this server does not rank")
				assert.Equal(t, 0, ACRLevel(raw).Priority(),
					"and it must rank 0, which is what makes keeping the value safe")
			})
		}
	})
}

// =============================================================================
// Property-based tests for mathematical properties
// =============================================================================

func TestACRLevel_MathematicalProperties(t *testing.T) {
	allLevels := []ACRLevel{ACRLevel1, ACRLevel2Optional, ACRLevel2Mandatory}

	t.Run("Transitivity: if a > b and b > c then a > c", func(t *testing.T) {
		// level2_mandatory > level2_optional > level1
		// Therefore: level2_mandatory > level1
		assert.True(t, ACRLevel2Mandatory.IsHigherThan(ACRLevel2Optional))
		assert.True(t, ACRLevel2Optional.IsHigherThan(ACRLevel1))
		assert.True(t, ACRLevel2Mandatory.IsHigherThan(ACRLevel1))
	})

	t.Run("Antisymmetry: if a > b then NOT b > a", func(t *testing.T) {
		for _, a := range allLevels {
			for _, b := range allLevels {
				if a.IsHigherThan(b) {
					assert.False(t, b.IsHigherThan(a),
						"Antisymmetry violated: %s > %s but also %s > %s", a, b, b, a)
				}
			}
		}
	})

	t.Run("Irreflexivity: a is NOT higher than a", func(t *testing.T) {
		for _, level := range allLevels {
			assert.False(t, level.IsHigherThan(level),
				"Irreflexivity violated: %s > %s", level, level)
		}
	})

	t.Run("Trichotomy: exactly one of a < b, a == b, a > b is true", func(t *testing.T) {
		for _, a := range allLevels {
			for _, b := range allLevels {
				aHigher := a.IsHigherThan(b)
				bHigher := b.IsHigherThan(a)
				equal := a == b

				// Count how many are true
				trueCount := 0
				if aHigher {
					trueCount++
				}
				if bHigher {
					trueCount++
				}
				if equal {
					trueCount++
				}

				assert.Equal(t, 1, trueCount,
					"Trichotomy violated for %s and %s: aHigher=%v, bHigher=%v, equal=%v",
					a, b, aHigher, bHigher, equal)
			}
		}
	})

	t.Run("ACRMax is associative: max(max(a,b),c) == max(a,max(b,c))", func(t *testing.T) {
		for _, a := range allLevels {
			for _, b := range allLevels {
				for _, c := range allLevels {
					left := ACRMax(ACRMax(a, b), c)
					right := ACRMax(a, ACRMax(b, c))
					assert.Equal(t, left, right,
						"Associativity violated: max(max(%s,%s),%s) != max(%s,max(%s,%s))",
						a, b, c, a, b, c)
				}
			}
		}
	})

	t.Run("ACRMax is idempotent: max(a,a) == a", func(t *testing.T) {
		for _, level := range allLevels {
			assert.Equal(t, level, ACRMax(level, level),
				"Idempotency violated: max(%s,%s) != %s", level, level, level)
		}
	})
}

// =============================================================================
// Integration test: verify priority map covers all defined ACR levels
// =============================================================================

func TestACRLevel_PriorityMapCompleteness(t *testing.T) {
	t.Run("All defined ACR levels have a priority", func(t *testing.T) {
		// This test ensures that if someone adds a new ACRLevel constant,
		// they must also add it to the priority map
		definedLevels := []ACRLevel{ACRLevel1, ACRLevel2Optional, ACRLevel2Mandatory}

		for _, level := range definedLevels {
			priority := level.Priority()
			assert.Positive(t, priority,
				"ACR level %s should have a priority > 0 (got %d)", level, priority)
		}
	})

	t.Run("Priority values are unique", func(t *testing.T) {
		definedLevels := []ACRLevel{ACRLevel1, ACRLevel2Optional, ACRLevel2Mandatory}
		seenPriorities := make(map[int]ACRLevel)

		for _, level := range definedLevels {
			priority := level.Priority()
			if existing, found := seenPriorities[priority]; found {
				t.Errorf("Priority %d is shared by %s and %s", priority, existing, level)
			}
			seenPriorities[priority] = level
		}
	})

	t.Run("Priority values are consecutive starting from 1", func(t *testing.T) {
		definedLevels := []ACRLevel{ACRLevel1, ACRLevel2Optional, ACRLevel2Mandatory}
		priorities := make([]int, len(definedLevels))

		for i, level := range definedLevels {
			priorities[i] = level.Priority()
		}

		// Check that we have 1, 2, 3
		expectedPriorities := map[int]bool{1: true, 2: true, 3: true}
		for _, p := range priorities {
			if !expectedPriorities[p] {
				t.Errorf("Unexpected priority value: %d", p)
			}
			delete(expectedPriorities, p)
		}

		if len(expectedPriorities) > 0 {
			t.Errorf("Missing priority values: %v", expectedPriorities)
		}
	})
}
