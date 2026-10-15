package authflow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/leodip/goiabada/authserver/internal/ceremony"
	"github.com/leodip/goiabada/authserver/internal/record"
)

// The reference decideCompletion is held to: the decision as it stood when the plan was a struct of
// flags, before the plan became three modes (#580). Nothing here may follow a later change to
// decideCompletion: a change to which arm a ceremony takes, or to what an arm does, is a change of
// behavior and is made here deliberately, with the reason, or not at all.

// frozenCompletionArm is the arm, as the reference names it.
type frozenCompletionArm int

const (
	frozenArmReuse frozenCompletionArm = iota + 1
	frozenArmCreate
	frozenArmRestart
)

// frozenCompletionPlan is the reference's answer: the arm, and every flag of every arm, false on the
// arms it does not belong to.
type frozenCompletionPlan struct {
	arm frozenCompletionArm

	rotateIdentifier           bool
	refreshAuthTime            bool
	replaceAuthentication      bool
	promoteOtpConfigGeneration bool

	terminateForeignSession bool
	replaceOwnSession       bool
}

// String names the arm and every flag set, for a failure message.
func (p frozenCompletionPlan) String() string {
	arms := map[frozenCompletionArm]string{frozenArmReuse: "reuse", frozenArmCreate: "create", frozenArmRestart: "restart"}
	flags := []struct {
		set  bool
		name string
	}{
		{p.rotateIdentifier, "rotateIdentifier"},
		{p.refreshAuthTime, "refreshAuthTime"},
		{p.replaceAuthentication, "replaceAuthentication"},
		{p.promoteOtpConfigGeneration, "promoteOtpConfigGeneration"},
		{p.terminateForeignSession, "terminateForeignSession"},
		{p.replaceOwnSession, "replaceOwnSession"},
	}
	described := arms[p.arm]
	for _, flag := range flags {
		if flag.set {
			described += " " + flag.name
		}
	}
	return described
}

// frozenDecideCompletion is decideCompletion as it stood, copied and left alone.
func frozenDecideCompletion(f completionFacts) frozenCompletionPlan {
	if f.sessionValid && f.sessionOwned {
		return frozenCompletionPlan{
			arm:                        frozenArmReuse,
			rotateIdentifier:           f.raisesPrivilege,
			refreshAuthTime:            f.credentialEntered,
			replaceAuthentication:      f.level1Completed,
			promoteOtpConfigGeneration: f.otpConfigGenerationCaptured && ceremony.TargetRequiresSecondFactor(f.target),
		}
	}
	if !f.level1Completed {
		return frozenCompletionPlan{arm: frozenArmRestart}
	}
	return frozenCompletionPlan{
		arm:                     frozenArmCreate,
		terminateForeignSession: f.sessionPresent && !f.sessionOwned,
		replaceOwnSession:       f.sessionPresent && f.sessionOwned,
	}
}

// frozenShapeOf reads a plan as the reference states one. It is a reading, not a decision: each
// mode's attributes land in the flags of the same name, and a mode leaves the other arms' flags false.
func frozenShapeOf(t *testing.T, plan completionPlan) frozenCompletionPlan {
	t.Helper()

	switch p := plan.(type) {
	case reuseSessionPlan:
		return frozenCompletionPlan{
			arm:                        frozenArmReuse,
			rotateIdentifier:           p.rotateIdentifier,
			refreshAuthTime:            p.refreshAuthTime,
			replaceAuthentication:      p.replaceAuthentication,
			promoteOtpConfigGeneration: p.promoteOtpConfigGeneration,
		}
	case createSessionPlan:
		return frozenCompletionPlan{
			arm:                     frozenArmCreate,
			terminateForeignSession: p.arrivedWith == arrivedWithForeignSession,
			replaceOwnSession:       p.arrivedWith == arrivedWithOwnSession,
		}
	case restartPlan:
		return frozenCompletionPlan{arm: frozenArmRestart}
	default:
		t.Fatalf("decideCompletion answered %T, which is none of the three modes", plan)
		return frozenCompletionPlan{}
	}
}

// everyCompletionFacts is every combination of the completion facts: each of the seven booleans
// both ways, against every target level and the empty one a client with no level would carry.
func everyCompletionFacts() []completionFacts {
	targets := []record.AcrLevel{"", record.AcrLevel1, record.AcrLevel2Optional, record.AcrLevel2Mandatory}
	var all []completionFacts
	for bits := 0; bits < 1<<7; bits++ {
		for _, target := range targets {
			all = append(all, completionFacts{
				sessionPresent:              bits&(1<<0) != 0,
				sessionValid:                bits&(1<<1) != 0,
				sessionOwned:                bits&(1<<2) != 0,
				level1Completed:             bits&(1<<3) != 0,
				credentialEntered:           bits&(1<<4) != 0,
				raisesPrivilege:             bits&(1<<5) != 0,
				otpConfigGenerationCaptured: bits&(1<<6) != 0,
				target:                      target,
			})
		}
	}
	return all
}

// decideCompletion answers what the reference answers, for every combination of the facts.
func TestDecideCompletion_MatchesTheFrozenReferenceForEveryCombination(t *testing.T) {
	all := everyCompletionFacts()
	assert.Len(t, all, 512)

	arms := map[frozenCompletionArm]int{}
	for _, facts := range all {
		want := frozenDecideCompletion(facts)
		arms[want.arm]++
		assert.Equal(t, want, frozenShapeOf(t, decideCompletion(facts)), "facts %+v, which the reference answers %v",
			facts, want)
	}
	// Every arm is reached, so the table is no vacuous agreement on one of them.
	assert.Equal(t, map[frozenCompletionArm]int{frozenArmReuse: 128, frozenArmCreate: 192, frozenArmRestart: 192}, arms)
}

// Each mode's constructor stores what it is given and nothing else.
func TestCompletionPlanModes_TheirConstructors(t *testing.T) {
	assert.Equal(t, reuseSessionPlan{rotateIdentifier: true}, reuseSession(true, false, false, false))
	assert.Equal(t, reuseSessionPlan{refreshAuthTime: true}, reuseSession(false, true, false, false))
	assert.Equal(t, reuseSessionPlan{replaceAuthentication: true}, reuseSession(false, false, true, false))
	assert.Equal(t, reuseSessionPlan{promoteOtpConfigGeneration: true}, reuseSession(false, false, false, true))

	assert.Equal(t, createSessionPlan{arrivedWith: arrivedWithNoSession}, createSession(arrivedWithNoSession))
	assert.Equal(t, createSessionPlan{arrivedWith: arrivedWithForeignSession}, createSession(arrivedWithForeignSession))
	assert.Equal(t, createSessionPlan{arrivedWith: arrivedWithOwnSession}, createSession(arrivedWithOwnSession))

	assert.Equal(t, restartPlan{}, restartAtLevel1())
}

// The create mode's two attributes, read off the one value that keeps them exclusive.
func TestCreateSessionPlan_TerminatesOrReplacesTheArrivedWithSession(t *testing.T) {
	testCases := []struct {
		arrivedWith   arrivedWithSession
		wantTerminate bool
		wantReplace   bool
	}{
		{arrivedWithNoSession, false, false},
		{arrivedWithForeignSession, true, false},
		{arrivedWithOwnSession, false, true},
	}
	for _, tc := range testCases {
		plan := createSession(tc.arrivedWith)
		assert.Equal(t, tc.wantTerminate, plan.terminatesForeignSession(), "%v", tc.arrivedWith)
		assert.Equal(t, tc.wantReplace, plan.replacesOwnSession(), "%v", tc.arrivedWith)
	}
}
