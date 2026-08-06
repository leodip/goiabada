# 6. Plan

Four stages. Stage 1 is the pure matcher, stage 2 the column and its two narrow writes, stage 3
enforcement in the browser flow, stage 4 enforcement in the account API plus the reset on disable.
Sections 0 to 5 are in `agreement.md` and every stage builds from them, not from this file alone.

Stage order is forced by dependency: stage 3 cannot claim a counter that stage 2 has not created, and
the repair of `test/reenroll-same-window` (decision 8) needs `ResetUserOTPStep`, so it lands in
stage 3 against stage 2's method.

### Stage 1: the step matcher
Status: **Done**
Landed 2026-08-06, code at `01a186c`, closed at `7841920`. Account in `log/stage-1.md`.

### Stage 2: the column and its two narrow writes
Status: **Done**
Landed 2026-08-06, commit `21cdef8`. Account in `log/stage-2.md`.

### Stage 3: enforcement in the browser flow
Status: **Done**
Landed 2026-08-06, commit `a856e4b`. Account in `log/stage-3.md`.

### Stage 4: the account API, and reset on disable
Status: **Done**
Landed 2026-08-06, commit `75332b8`. Account in `log/stage-4.md`.
