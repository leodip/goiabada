package enums

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Tests for AcrLevel.Priority()
// =============================================================================

func TestAcrLevel_Priority(t *testing.T) {
	t.Run("All known ACR levels have correct priority ordering", func(t *testing.T) {
		// Verify exact priority values
		assert.Equal(t, 1, AcrLevel1.Priority(), "AcrLevel1 should have priority 1")
		assert.Equal(t, 2, AcrLevel2Optional.Priority(), "AcrLevel2Optional should have priority 2")
		assert.Equal(t, 3, AcrLevel2Mandatory.Priority(), "AcrLevel2Mandatory should have priority 3")

		// Verify ordering relationships
		assert.Less(t, AcrLevel1.Priority(), AcrLevel2Optional.Priority(),
			"level1 priority should be less than level2_optional priority")
		assert.Less(t, AcrLevel2Optional.Priority(), AcrLevel2Mandatory.Priority(),
			"level2_optional priority should be less than level2_mandatory priority")
		assert.Less(t, AcrLevel1.Priority(), AcrLevel2Mandatory.Priority(),
			"level1 priority should be less than level2_mandatory priority")
	})

	t.Run("Unknown ACR level returns 0", func(t *testing.T) {
		testCases := []struct {
			name     string
			acrLevel AcrLevel
		}{
			{"arbitrary unknown string", AcrLevel("unknown:acr:level")},
			{"empty string", AcrLevel("")},
			{"whitespace only", AcrLevel("   ")},
			{"similar but wrong format", AcrLevel("urn:goiabada:level3")},
			{"partial match", AcrLevel("level1")},
			{"case sensitive check", AcrLevel("urn:goiabada:LEVEL1")},
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
// Tests for AcrLevel.IsHigherThan() - Exhaustive 3x3 matrix
// =============================================================================

func TestAcrLevel_IsHigherThan_ExhaustiveMatrix(t *testing.T) {
	// Define all ACR levels for exhaustive testing
	allLevels := []AcrLevel{AcrLevel1, AcrLevel2Optional, AcrLevel2Mandatory}

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

func TestAcrLevel_IsHigherThan_UnknownACR(t *testing.T) {
	unknown := AcrLevel("unknown")
	empty := AcrLevel("")

	t.Run("unknown ACR vs all known ACRs", func(t *testing.T) {
		// Unknown (priority 0) is never higher than known levels (priority >= 1)
		assert.False(t, unknown.IsHigherThan(AcrLevel1))
		assert.False(t, unknown.IsHigherThan(AcrLevel2Optional))
		assert.False(t, unknown.IsHigherThan(AcrLevel2Mandatory))
	})

	t.Run("all known ACRs vs unknown ACR", func(t *testing.T) {
		// Known levels (priority >= 1) are always higher than unknown (priority 0)
		assert.True(t, AcrLevel1.IsHigherThan(unknown))
		assert.True(t, AcrLevel2Optional.IsHigherThan(unknown))
		assert.True(t, AcrLevel2Mandatory.IsHigherThan(unknown))
	})

	t.Run("empty ACR vs all known ACRs", func(t *testing.T) {
		assert.False(t, empty.IsHigherThan(AcrLevel1))
		assert.False(t, empty.IsHigherThan(AcrLevel2Optional))
		assert.False(t, empty.IsHigherThan(AcrLevel2Mandatory))
	})

	t.Run("all known ACRs vs empty ACR", func(t *testing.T) {
		assert.True(t, AcrLevel1.IsHigherThan(empty))
		assert.True(t, AcrLevel2Optional.IsHigherThan(empty))
		assert.True(t, AcrLevel2Mandatory.IsHigherThan(empty))
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
// Tests for AcrLevel.IsHigherOrEqualTo() - Exhaustive 3x3 matrix
// =============================================================================

func TestAcrLevel_IsHigherOrEqualTo_ExhaustiveMatrix(t *testing.T) {
	allLevels := []AcrLevel{AcrLevel1, AcrLevel2Optional, AcrLevel2Mandatory}

	// Expected results for IsHigherOrEqualTo(row, col)
	//
	//                    col: level1  level2_opt  level2_mand
	// row: level1               true      false        false
	// row: level2_optional      true       true        false
	// row: level2_mandatory     true       true         true
	expectedMatrix := [][]bool{
		{true, false, false}, // level1 is >= only itself
		{true, true, false},  // level2_optional is >= level1 and itself
		{true, true, true},   // level2_mandatory is >= all
	}

	for i, rowLevel := range allLevels {
		for j, colLevel := range allLevels {
			expected := expectedMatrix[i][j]
			t.Run(rowLevel.String()+"_vs_"+colLevel.String(), func(t *testing.T) {
				result := rowLevel.IsHigherOrEqualTo(colLevel)
				assert.Equal(t, expected, result,
					"%s.IsHigherOrEqualTo(%s) should be %v", rowLevel, colLevel, expected)
			})
		}
	}
}

func TestAcrLevel_IsHigherOrEqualTo_UnknownACR(t *testing.T) {
	unknown := AcrLevel("unknown")
	empty := AcrLevel("")

	t.Run("unknown ACR vs all known ACRs", func(t *testing.T) {
		// Unknown (priority 0) is never >= known levels (priority >= 1)
		assert.False(t, unknown.IsHigherOrEqualTo(AcrLevel1))
		assert.False(t, unknown.IsHigherOrEqualTo(AcrLevel2Optional))
		assert.False(t, unknown.IsHigherOrEqualTo(AcrLevel2Mandatory))
	})

	t.Run("all known ACRs vs unknown ACR", func(t *testing.T) {
		// Known levels (priority >= 1) are always >= unknown (priority 0)
		assert.True(t, AcrLevel1.IsHigherOrEqualTo(unknown))
		assert.True(t, AcrLevel2Optional.IsHigherOrEqualTo(unknown))
		assert.True(t, AcrLevel2Mandatory.IsHigherOrEqualTo(unknown))
	})

	t.Run("unknown vs unknown (equal priorities)", func(t *testing.T) {
		// Both have priority 0, so they are "equal" (0 >= 0)
		assert.True(t, unknown.IsHigherOrEqualTo(unknown))
		assert.True(t, empty.IsHigherOrEqualTo(empty))
		assert.True(t, unknown.IsHigherOrEqualTo(empty))
		assert.True(t, empty.IsHigherOrEqualTo(unknown))
	})
}

// =============================================================================
// Tests for AcrMax() - Exhaustive 3x3 matrix
// =============================================================================

func TestAcrMax_ExhaustiveMatrix(t *testing.T) {
	allLevels := []AcrLevel{AcrLevel1, AcrLevel2Optional, AcrLevel2Mandatory}

	// Expected results for AcrMax(row, col)
	// The result should always be the higher of the two
	//
	//                    col: level1       level2_opt       level2_mand
	// row: level1              level1      level2_opt       level2_mand
	// row: level2_optional     level2_opt  level2_opt       level2_mand
	// row: level2_mandatory    level2_mand level2_mand      level2_mand
	expectedMatrix := [][]AcrLevel{
		{AcrLevel1, AcrLevel2Optional, AcrLevel2Mandatory},
		{AcrLevel2Optional, AcrLevel2Optional, AcrLevel2Mandatory},
		{AcrLevel2Mandatory, AcrLevel2Mandatory, AcrLevel2Mandatory},
	}

	for i, rowLevel := range allLevels {
		for j, colLevel := range allLevels {
			expected := expectedMatrix[i][j]
			t.Run(rowLevel.String()+"_and_"+colLevel.String(), func(t *testing.T) {
				result := AcrMax(rowLevel, colLevel)
				assert.Equal(t, expected, result,
					"AcrMax(%s, %s) should be %s", rowLevel, colLevel, expected)
			})
		}
	}
}

func TestAcrMax_Commutativity(t *testing.T) {
	// AcrMax should be commutative: AcrMax(a, b) == AcrMax(b, a)
	allLevels := []AcrLevel{AcrLevel1, AcrLevel2Optional, AcrLevel2Mandatory}

	for _, a := range allLevels {
		for _, b := range allLevels {
			t.Run(a.String()+"_commutes_with_"+b.String(), func(t *testing.T) {
				assert.Equal(t, AcrMax(a, b), AcrMax(b, a),
					"AcrMax should be commutative: AcrMax(%s, %s) == AcrMax(%s, %s)",
					a, b, b, a)
			})
		}
	}
}

func TestAcrMax_UnknownACR(t *testing.T) {
	unknown := AcrLevel("unknown")
	empty := AcrLevel("")

	t.Run("max of known and unknown returns known", func(t *testing.T) {
		// When one is known (priority > 0) and one is unknown (priority 0),
		// the known one should be returned
		assert.Equal(t, AcrLevel1, AcrMax(AcrLevel1, unknown))
		assert.Equal(t, AcrLevel1, AcrMax(unknown, AcrLevel1))

		assert.Equal(t, AcrLevel2Optional, AcrMax(AcrLevel2Optional, unknown))
		assert.Equal(t, AcrLevel2Optional, AcrMax(unknown, AcrLevel2Optional))

		assert.Equal(t, AcrLevel2Mandatory, AcrMax(AcrLevel2Mandatory, unknown))
		assert.Equal(t, AcrLevel2Mandatory, AcrMax(unknown, AcrLevel2Mandatory))
	})

	t.Run("max of known and empty returns known", func(t *testing.T) {
		assert.Equal(t, AcrLevel1, AcrMax(AcrLevel1, empty))
		assert.Equal(t, AcrLevel1, AcrMax(empty, AcrLevel1))

		assert.Equal(t, AcrLevel2Optional, AcrMax(AcrLevel2Optional, empty))
		assert.Equal(t, AcrLevel2Optional, AcrMax(empty, AcrLevel2Optional))

		assert.Equal(t, AcrLevel2Mandatory, AcrMax(AcrLevel2Mandatory, empty))
		assert.Equal(t, AcrLevel2Mandatory, AcrMax(empty, AcrLevel2Mandatory))
	})

	t.Run("max of two unknowns returns first argument", func(t *testing.T) {
		// When both have priority 0, AcrMax returns first argument (a >= b is true when both are 0)
		unknown1 := AcrLevel("unknown1")
		unknown2 := AcrLevel("unknown2")

		assert.Equal(t, unknown1, AcrMax(unknown1, unknown2))
		assert.Equal(t, unknown2, AcrMax(unknown2, unknown1))
		assert.Equal(t, unknown, AcrMax(unknown, empty))
		assert.Equal(t, empty, AcrMax(empty, unknown))
	})
}

// =============================================================================
// Tests for AcrLevelFromString()
// =============================================================================

func TestAcrLevelFromString(t *testing.T) {
	t.Run("Valid ACR strings return correct levels", func(t *testing.T) {
		testCases := []struct {
			input    string
			expected AcrLevel
		}{
			{"urn:goiabada:level1", AcrLevel1},
			{"urn:goiabada:level2_optional", AcrLevel2Optional},
			{"urn:goiabada:level2_mandatory", AcrLevel2Mandatory},
		}

		for _, tc := range testCases {
			t.Run(tc.input, func(t *testing.T) {
				level, err := AcrLevelFromString(tc.input)
				assert.NoError(t, err)
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
				_, err := AcrLevelFromString(tc.input)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid ACR level")
			})
		}
	})
}

// =============================================================================
// Tests for AcrLevel.String()
// =============================================================================

func TestAcrLevel_String(t *testing.T) {
	t.Run("All known ACR levels return correct strings", func(t *testing.T) {
		assert.Equal(t, "urn:goiabada:level1", AcrLevel1.String())
		assert.Equal(t, "urn:goiabada:level2_optional", AcrLevel2Optional.String())
		assert.Equal(t, "urn:goiabada:level2_mandatory", AcrLevel2Mandatory.String())
	})

	t.Run("String and AcrLevelFromString are inverse operations", func(t *testing.T) {
		allLevels := []AcrLevel{AcrLevel1, AcrLevel2Optional, AcrLevel2Mandatory}

		for _, level := range allLevels {
			t.Run(level.String(), func(t *testing.T) {
				// Convert to string and back
				str := level.String()
				parsed, err := AcrLevelFromString(str)
				assert.NoError(t, err)
				assert.Equal(t, level, parsed)
			})
		}
	})
}

// =============================================================================
// Property-based tests for mathematical properties
// =============================================================================

func TestAcrLevel_MathematicalProperties(t *testing.T) {
	allLevels := []AcrLevel{AcrLevel1, AcrLevel2Optional, AcrLevel2Mandatory}

	t.Run("Transitivity: if a > b and b > c then a > c", func(t *testing.T) {
		// level2_mandatory > level2_optional > level1
		// Therefore: level2_mandatory > level1
		assert.True(t, AcrLevel2Mandatory.IsHigherThan(AcrLevel2Optional))
		assert.True(t, AcrLevel2Optional.IsHigherThan(AcrLevel1))
		assert.True(t, AcrLevel2Mandatory.IsHigherThan(AcrLevel1))
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

	t.Run("AcrMax is associative: max(max(a,b),c) == max(a,max(b,c))", func(t *testing.T) {
		for _, a := range allLevels {
			for _, b := range allLevels {
				for _, c := range allLevels {
					left := AcrMax(AcrMax(a, b), c)
					right := AcrMax(a, AcrMax(b, c))
					assert.Equal(t, left, right,
						"Associativity violated: max(max(%s,%s),%s) != max(%s,max(%s,%s))",
						a, b, c, a, b, c)
				}
			}
		}
	})

	t.Run("AcrMax is idempotent: max(a,a) == a", func(t *testing.T) {
		for _, level := range allLevels {
			assert.Equal(t, level, AcrMax(level, level),
				"Idempotency violated: max(%s,%s) != %s", level, level, level)
		}
	})
}

// =============================================================================
// Integration test: verify priority map covers all defined ACR levels
// =============================================================================

func TestAcrLevel_PriorityMapCompleteness(t *testing.T) {
	t.Run("All defined ACR levels have a priority", func(t *testing.T) {
		// This test ensures that if someone adds a new AcrLevel constant,
		// they must also add it to the priority map
		definedLevels := []AcrLevel{AcrLevel1, AcrLevel2Optional, AcrLevel2Mandatory}

		for _, level := range definedLevels {
			priority := level.Priority()
			assert.Greater(t, priority, 0,
				"ACR level %s should have a priority > 0 (got %d)", level, priority)
		}
	})

	t.Run("Priority values are unique", func(t *testing.T) {
		definedLevels := []AcrLevel{AcrLevel1, AcrLevel2Optional, AcrLevel2Mandatory}
		seenPriorities := make(map[int]AcrLevel)

		for _, level := range definedLevels {
			priority := level.Priority()
			if existing, found := seenPriorities[priority]; found {
				t.Errorf("Priority %d is shared by %s and %s", priority, existing, level)
			}
			seenPriorities[priority] = level
		}
	})

	t.Run("Priority values are consecutive starting from 1", func(t *testing.T) {
		definedLevels := []AcrLevel{AcrLevel1, AcrLevel2Optional, AcrLevel2Mandatory}
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
