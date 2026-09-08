package pagination

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// expectedTable is the whole behaviour of the bar, one row per call: every page
// count from 0 to 12 at the page size the admin console uses, with every
// current page from 1 before the first to two past the last, then the exact
// multiples, the clamps, the narrow windows and the audit log's page size.
//
// Each row reads "total=... size=... cur=... n=... | prev=<has> <n> next=<has>
// <n> | <bar>", where the bar writes the current page as [n] and an ellipsis as
// "...".
//
// The 73 rows carrying a "<- was:" suffix are the ones where this package
// answers differently from the unmaintained library it replaced, and the suffix
// records what that library drew. Every one of them is a place where a single
// hidden page became that page's number instead of dots (#271). They are
// correct as written: restoring the library's answer there is a regression, not
// a fix. The suffix is parsed off and never compared.
//
// The three rows under "# defensive clamps" pin the out-of-range handling on
// purpose, since a page number arrives from a query parameter.
const expectedTable = `
# sweep: size=10, totals giving 0..12 pages (last page partial), cur=1..pages+2
total=0    size=10  cur=1   n=5 | prev=false 1  next=false 1  | [1]
total=0    size=10  cur=2   n=5 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=1   n=5 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=2   n=5 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=3   n=5 | prev=false 1  next=false 1  | [1]
total=13   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2
total=13   size=10  cur=2   n=5 | prev=true  1  next=false 2  | 1 [2]
total=13   size=10  cur=3   n=5 | prev=true  1  next=false 2  | 1 [2]
total=13   size=10  cur=4   n=5 | prev=true  1  next=false 2  | 1 [2]
total=23   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3
total=23   size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3
total=23   size=10  cur=3   n=5 | prev=true  2  next=false 3  | 1 2 [3]
total=23   size=10  cur=4   n=5 | prev=true  2  next=false 3  | 1 2 [3]
total=23   size=10  cur=5   n=5 | prev=true  2  next=false 3  | 1 2 [3]
total=33   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4
total=33   size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4
total=33   size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4
total=33   size=10  cur=4   n=5 | prev=true  3  next=false 4  | 1 2 3 [4]
total=33   size=10  cur=5   n=5 | prev=true  3  next=false 4  | 1 2 3 [4]
total=33   size=10  cur=6   n=5 | prev=true  3  next=false 4  | 1 2 3 [4]
total=43   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5
total=43   size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5
total=43   size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5
total=43   size=10  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5
total=43   size=10  cur=5   n=5 | prev=true  4  next=false 5  | 1 2 3 4 [5]
total=43   size=10  cur=6   n=5 | prev=true  4  next=false 5  | 1 2 3 4 [5]
total=43   size=10  cur=7   n=5 | prev=true  4  next=false 5  | 1 2 3 4 [5]
total=53   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5 6  <- was: [1] 2 3 4 5 ...
total=53   size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5 6  <- was: 1 [2] 3 4 5 ...
total=53   size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5 6  <- was: 1 2 [3] 4 5 ...
total=53   size=10  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5 6  <- was: ... 2 3 [4] 5 6
total=53   size=10  cur=5   n=5 | prev=true  4  next=true  6  | 1 2 3 4 [5] 6  <- was: ... 2 3 4 [5] 6
total=53   size=10  cur=6   n=5 | prev=true  5  next=false 6  | 1 2 3 4 5 [6]  <- was: ... 2 3 4 5 [6]
total=53   size=10  cur=7   n=5 | prev=true  5  next=false 6  | 1 2 3 4 5 [6]  <- was: ... 2 3 4 5 [6]
total=53   size=10  cur=8   n=5 | prev=true  5  next=false 6  | 1 2 3 4 5 [6]  <- was: ... 2 3 4 5 [6]
total=63   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5 ...
total=63   size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5 ...
total=63   size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5 ...
total=63   size=10  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5 6 7  <- was: ... 2 3 [4] 5 6 ...
total=63   size=10  cur=5   n=5 | prev=true  4  next=true  6  | ... 3 4 [5] 6 7
total=63   size=10  cur=6   n=5 | prev=true  5  next=true  7  | ... 3 4 5 [6] 7
total=63   size=10  cur=7   n=5 | prev=true  6  next=false 7  | ... 3 4 5 6 [7]
total=63   size=10  cur=8   n=5 | prev=true  6  next=false 7  | ... 3 4 5 6 [7]
total=63   size=10  cur=9   n=5 | prev=true  6  next=false 7  | ... 3 4 5 6 [7]
total=73   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5 ...
total=73   size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5 ...
total=73   size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5 ...
total=73   size=10  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5 6 ...  <- was: ... 2 3 [4] 5 6 ...
total=73   size=10  cur=5   n=5 | prev=true  4  next=true  6  | ... 3 4 [5] 6 7 8  <- was: ... 3 4 [5] 6 7 ...
total=73   size=10  cur=6   n=5 | prev=true  5  next=true  7  | ... 4 5 [6] 7 8
total=73   size=10  cur=7   n=5 | prev=true  6  next=true  8  | ... 4 5 6 [7] 8
total=73   size=10  cur=8   n=5 | prev=true  7  next=false 8  | ... 4 5 6 7 [8]
total=73   size=10  cur=9   n=5 | prev=true  7  next=false 8  | ... 4 5 6 7 [8]
total=73   size=10  cur=10  n=5 | prev=true  7  next=false 8  | ... 4 5 6 7 [8]
total=83   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5 ...
total=83   size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5 ...
total=83   size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5 ...
total=83   size=10  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5 6 ...  <- was: ... 2 3 [4] 5 6 ...
total=83   size=10  cur=5   n=5 | prev=true  4  next=true  6  | ... 3 4 [5] 6 7 ...
total=83   size=10  cur=6   n=5 | prev=true  5  next=true  7  | ... 4 5 [6] 7 8 9  <- was: ... 4 5 [6] 7 8 ...
total=83   size=10  cur=7   n=5 | prev=true  6  next=true  8  | ... 5 6 [7] 8 9
total=83   size=10  cur=8   n=5 | prev=true  7  next=true  9  | ... 5 6 7 [8] 9
total=83   size=10  cur=9   n=5 | prev=true  8  next=false 9  | ... 5 6 7 8 [9]
total=83   size=10  cur=10  n=5 | prev=true  8  next=false 9  | ... 5 6 7 8 [9]
total=83   size=10  cur=11  n=5 | prev=true  8  next=false 9  | ... 5 6 7 8 [9]
total=93   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5 ...
total=93   size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5 ...
total=93   size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5 ...
total=93   size=10  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5 6 ...  <- was: ... 2 3 [4] 5 6 ...
total=93   size=10  cur=5   n=5 | prev=true  4  next=true  6  | ... 3 4 [5] 6 7 ...
total=93   size=10  cur=6   n=5 | prev=true  5  next=true  7  | ... 4 5 [6] 7 8 ...
total=93   size=10  cur=7   n=5 | prev=true  6  next=true  8  | ... 5 6 [7] 8 9 10  <- was: ... 5 6 [7] 8 9 ...
total=93   size=10  cur=8   n=5 | prev=true  7  next=true  9  | ... 6 7 [8] 9 10
total=93   size=10  cur=9   n=5 | prev=true  8  next=true  10 | ... 6 7 8 [9] 10
total=93   size=10  cur=10  n=5 | prev=true  9  next=false 10 | ... 6 7 8 9 [10]
total=93   size=10  cur=11  n=5 | prev=true  9  next=false 10 | ... 6 7 8 9 [10]
total=93   size=10  cur=12  n=5 | prev=true  9  next=false 10 | ... 6 7 8 9 [10]
total=103  size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5 ...
total=103  size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5 ...
total=103  size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5 ...
total=103  size=10  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5 6 ...  <- was: ... 2 3 [4] 5 6 ...
total=103  size=10  cur=5   n=5 | prev=true  4  next=true  6  | ... 3 4 [5] 6 7 ...
total=103  size=10  cur=6   n=5 | prev=true  5  next=true  7  | ... 4 5 [6] 7 8 ...
total=103  size=10  cur=7   n=5 | prev=true  6  next=true  8  | ... 5 6 [7] 8 9 ...
total=103  size=10  cur=8   n=5 | prev=true  7  next=true  9  | ... 6 7 [8] 9 10 11  <- was: ... 6 7 [8] 9 10 ...
total=103  size=10  cur=9   n=5 | prev=true  8  next=true  10 | ... 7 8 [9] 10 11
total=103  size=10  cur=10  n=5 | prev=true  9  next=true  11 | ... 7 8 9 [10] 11
total=103  size=10  cur=11  n=5 | prev=true  10 next=false 11 | ... 7 8 9 10 [11]
total=103  size=10  cur=12  n=5 | prev=true  10 next=false 11 | ... 7 8 9 10 [11]
total=103  size=10  cur=13  n=5 | prev=true  10 next=false 11 | ... 7 8 9 10 [11]
total=113  size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5 ...
total=113  size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5 ...
total=113  size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5 ...
total=113  size=10  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5 6 ...  <- was: ... 2 3 [4] 5 6 ...
total=113  size=10  cur=5   n=5 | prev=true  4  next=true  6  | ... 3 4 [5] 6 7 ...
total=113  size=10  cur=6   n=5 | prev=true  5  next=true  7  | ... 4 5 [6] 7 8 ...
total=113  size=10  cur=7   n=5 | prev=true  6  next=true  8  | ... 5 6 [7] 8 9 ...
total=113  size=10  cur=8   n=5 | prev=true  7  next=true  9  | ... 6 7 [8] 9 10 ...
total=113  size=10  cur=9   n=5 | prev=true  8  next=true  10 | ... 7 8 [9] 10 11 12  <- was: ... 7 8 [9] 10 11 ...
total=113  size=10  cur=10  n=5 | prev=true  9  next=true  11 | ... 8 9 [10] 11 12
total=113  size=10  cur=11  n=5 | prev=true  10 next=true  12 | ... 8 9 10 [11] 12
total=113  size=10  cur=12  n=5 | prev=true  11 next=false 12 | ... 8 9 10 11 [12]
total=113  size=10  cur=13  n=5 | prev=true  11 next=false 12 | ... 8 9 10 11 [12]
total=113  size=10  cur=14  n=5 | prev=true  11 next=false 12 | ... 8 9 10 11 [12]
# exact multiples: total divisible by size
total=10   size=10  cur=1   n=5 | prev=false 1  next=false 1  | [1]
total=10   size=10  cur=2   n=5 | prev=false 1  next=false 1  | [1]
total=20   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2
total=20   size=10  cur=2   n=5 | prev=true  1  next=false 2  | 1 [2]
total=20   size=10  cur=3   n=5 | prev=true  1  next=false 2  | 1 [2]
total=50   size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5
total=50   size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5
total=50   size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5
total=50   size=10  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5
total=50   size=10  cur=5   n=5 | prev=true  4  next=false 5  | 1 2 3 4 [5]
total=50   size=10  cur=6   n=5 | prev=true  4  next=false 5  | 1 2 3 4 [5]
total=100  size=10  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5 ...
total=100  size=10  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5 ...
total=100  size=10  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5 ...
total=100  size=10  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5 6 ...  <- was: ... 2 3 [4] 5 6 ...
total=100  size=10  cur=5   n=5 | prev=true  4  next=true  6  | ... 3 4 [5] 6 7 ...
total=100  size=10  cur=6   n=5 | prev=true  5  next=true  7  | ... 4 5 [6] 7 8 ...
total=100  size=10  cur=7   n=5 | prev=true  6  next=true  8  | ... 5 6 [7] 8 9 10  <- was: ... 5 6 [7] 8 9 ...
total=100  size=10  cur=8   n=5 | prev=true  7  next=true  9  | ... 6 7 [8] 9 10
total=100  size=10  cur=9   n=5 | prev=true  8  next=true  10 | ... 6 7 8 [9] 10
total=100  size=10  cur=10  n=5 | prev=true  9  next=false 10 | ... 6 7 8 9 [10]
total=100  size=10  cur=11  n=5 | prev=true  9  next=false 10 | ... 6 7 8 9 [10]
# defensive clamps in New: size<=0 -> 1, cur<=0 -> 1, cur>pages -> pages
total=0    size=-1  cur=-1  n=5 | prev=false 1  next=false 1  | [1]
total=25   size=0   cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5 ...
total=25   size=10  cur=0   n=5 | prev=false 1  next=true  2  | [1] 2 3
total=25   size=10  cur=99  n=5 | prev=true  2  next=false 3  | 1 2 [3]
# narrow windows: n=0..4, size=10, 0..8 pages, cur=1..pages+1
total=0    size=10  cur=1   n=0 | prev=false 1  next=false 1  | 
total=3    size=10  cur=1   n=0 | prev=false 1  next=false 1  | 
total=3    size=10  cur=2   n=0 | prev=false 1  next=false 1  | 
total=13   size=10  cur=1   n=0 | prev=false 1  next=true  2  | 
total=13   size=10  cur=2   n=0 | prev=true  1  next=false 2  | 
total=13   size=10  cur=3   n=0 | prev=true  1  next=false 2  | 
total=23   size=10  cur=1   n=0 | prev=false 1  next=true  2  | 
total=23   size=10  cur=2   n=0 | prev=true  1  next=true  3  | 
total=23   size=10  cur=3   n=0 | prev=true  2  next=false 3  | 
total=23   size=10  cur=4   n=0 | prev=true  2  next=false 3  | 
total=33   size=10  cur=1   n=0 | prev=false 1  next=true  2  | 
total=33   size=10  cur=2   n=0 | prev=true  1  next=true  3  | 
total=33   size=10  cur=3   n=0 | prev=true  2  next=true  4  | 
total=33   size=10  cur=4   n=0 | prev=true  3  next=false 4  | 
total=33   size=10  cur=5   n=0 | prev=true  3  next=false 4  | 
total=43   size=10  cur=1   n=0 | prev=false 1  next=true  2  | 
total=43   size=10  cur=2   n=0 | prev=true  1  next=true  3  | 
total=43   size=10  cur=3   n=0 | prev=true  2  next=true  4  | 
total=43   size=10  cur=4   n=0 | prev=true  3  next=true  5  | 
total=43   size=10  cur=5   n=0 | prev=true  4  next=false 5  | 
total=43   size=10  cur=6   n=0 | prev=true  4  next=false 5  | 
total=53   size=10  cur=1   n=0 | prev=false 1  next=true  2  | 
total=53   size=10  cur=2   n=0 | prev=true  1  next=true  3  | 
total=53   size=10  cur=3   n=0 | prev=true  2  next=true  4  | 
total=53   size=10  cur=4   n=0 | prev=true  3  next=true  5  | 
total=53   size=10  cur=5   n=0 | prev=true  4  next=true  6  | 
total=53   size=10  cur=6   n=0 | prev=true  5  next=false 6  | 
total=53   size=10  cur=7   n=0 | prev=true  5  next=false 6  | 
total=63   size=10  cur=1   n=0 | prev=false 1  next=true  2  | 
total=63   size=10  cur=2   n=0 | prev=true  1  next=true  3  | 
total=63   size=10  cur=3   n=0 | prev=true  2  next=true  4  | 
total=63   size=10  cur=4   n=0 | prev=true  3  next=true  5  | 
total=63   size=10  cur=5   n=0 | prev=true  4  next=true  6  | 
total=63   size=10  cur=6   n=0 | prev=true  5  next=true  7  | 
total=63   size=10  cur=7   n=0 | prev=true  6  next=false 7  | 
total=63   size=10  cur=8   n=0 | prev=true  6  next=false 7  | 
total=73   size=10  cur=1   n=0 | prev=false 1  next=true  2  | 
total=73   size=10  cur=2   n=0 | prev=true  1  next=true  3  | 
total=73   size=10  cur=3   n=0 | prev=true  2  next=true  4  | 
total=73   size=10  cur=4   n=0 | prev=true  3  next=true  5  | 
total=73   size=10  cur=5   n=0 | prev=true  4  next=true  6  | 
total=73   size=10  cur=6   n=0 | prev=true  5  next=true  7  | 
total=73   size=10  cur=7   n=0 | prev=true  6  next=true  8  | 
total=73   size=10  cur=8   n=0 | prev=true  7  next=false 8  | 
total=73   size=10  cur=9   n=0 | prev=true  7  next=false 8  | 
total=0    size=10  cur=1   n=1 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=1   n=1 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=2   n=1 | prev=false 1  next=false 1  | [1]
total=13   size=10  cur=1   n=1 | prev=false 1  next=true  2  | [1] 2  <- was: [1] ...
total=13   size=10  cur=2   n=1 | prev=true  1  next=false 2  | 1 [2]  <- was: ... [2]
total=13   size=10  cur=3   n=1 | prev=true  1  next=false 2  | 1 [2]  <- was: ... [2]
total=23   size=10  cur=1   n=1 | prev=false 1  next=true  2  | [1] ...
total=23   size=10  cur=2   n=1 | prev=true  1  next=true  3  | 1 [2] 3  <- was: ... [2] ...
total=23   size=10  cur=3   n=1 | prev=true  2  next=false 3  | ... [3]
total=23   size=10  cur=4   n=1 | prev=true  2  next=false 3  | ... [3]
total=33   size=10  cur=1   n=1 | prev=false 1  next=true  2  | [1] ...
total=33   size=10  cur=2   n=1 | prev=true  1  next=true  3  | 1 [2] ...  <- was: ... [2] ...
total=33   size=10  cur=3   n=1 | prev=true  2  next=true  4  | ... [3] 4  <- was: ... [3] ...
total=33   size=10  cur=4   n=1 | prev=true  3  next=false 4  | ... [4]
total=33   size=10  cur=5   n=1 | prev=true  3  next=false 4  | ... [4]
total=43   size=10  cur=1   n=1 | prev=false 1  next=true  2  | [1] ...
total=43   size=10  cur=2   n=1 | prev=true  1  next=true  3  | 1 [2] ...  <- was: ... [2] ...
total=43   size=10  cur=3   n=1 | prev=true  2  next=true  4  | ... [3] ...
total=43   size=10  cur=4   n=1 | prev=true  3  next=true  5  | ... [4] 5  <- was: ... [4] ...
total=43   size=10  cur=5   n=1 | prev=true  4  next=false 5  | ... [5]
total=43   size=10  cur=6   n=1 | prev=true  4  next=false 5  | ... [5]
total=53   size=10  cur=1   n=1 | prev=false 1  next=true  2  | [1] ...
total=53   size=10  cur=2   n=1 | prev=true  1  next=true  3  | 1 [2] ...  <- was: ... [2] ...
total=53   size=10  cur=3   n=1 | prev=true  2  next=true  4  | ... [3] ...
total=53   size=10  cur=4   n=1 | prev=true  3  next=true  5  | ... [4] ...
total=53   size=10  cur=5   n=1 | prev=true  4  next=true  6  | ... [5] 6  <- was: ... [5] ...
total=53   size=10  cur=6   n=1 | prev=true  5  next=false 6  | ... [6]
total=53   size=10  cur=7   n=1 | prev=true  5  next=false 6  | ... [6]
total=63   size=10  cur=1   n=1 | prev=false 1  next=true  2  | [1] ...
total=63   size=10  cur=2   n=1 | prev=true  1  next=true  3  | 1 [2] ...  <- was: ... [2] ...
total=63   size=10  cur=3   n=1 | prev=true  2  next=true  4  | ... [3] ...
total=63   size=10  cur=4   n=1 | prev=true  3  next=true  5  | ... [4] ...
total=63   size=10  cur=5   n=1 | prev=true  4  next=true  6  | ... [5] ...
total=63   size=10  cur=6   n=1 | prev=true  5  next=true  7  | ... [6] 7  <- was: ... [6] ...
total=63   size=10  cur=7   n=1 | prev=true  6  next=false 7  | ... [7]
total=63   size=10  cur=8   n=1 | prev=true  6  next=false 7  | ... [7]
total=73   size=10  cur=1   n=1 | prev=false 1  next=true  2  | [1] ...
total=73   size=10  cur=2   n=1 | prev=true  1  next=true  3  | 1 [2] ...  <- was: ... [2] ...
total=73   size=10  cur=3   n=1 | prev=true  2  next=true  4  | ... [3] ...
total=73   size=10  cur=4   n=1 | prev=true  3  next=true  5  | ... [4] ...
total=73   size=10  cur=5   n=1 | prev=true  4  next=true  6  | ... [5] ...
total=73   size=10  cur=6   n=1 | prev=true  5  next=true  7  | ... [6] ...
total=73   size=10  cur=7   n=1 | prev=true  6  next=true  8  | ... [7] 8  <- was: ... [7] ...
total=73   size=10  cur=8   n=1 | prev=true  7  next=false 8  | ... [8]
total=73   size=10  cur=9   n=1 | prev=true  7  next=false 8  | ... [8]
total=0    size=10  cur=1   n=2 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=1   n=2 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=2   n=2 | prev=false 1  next=false 1  | [1]
total=13   size=10  cur=1   n=2 | prev=false 1  next=true  2  | [1] 2
total=13   size=10  cur=2   n=2 | prev=true  1  next=false 2  | 1 [2]
total=13   size=10  cur=3   n=2 | prev=true  1  next=false 2  | 1 [2]
total=23   size=10  cur=1   n=2 | prev=false 1  next=true  2  | [1] 2 3  <- was: [1] 2 ...
total=23   size=10  cur=2   n=2 | prev=true  1  next=true  3  | 1 [2] 3  <- was: ... [2] 3
total=23   size=10  cur=3   n=2 | prev=true  2  next=false 3  | 1 2 [3]  <- was: ... 2 [3]
total=23   size=10  cur=4   n=2 | prev=true  2  next=false 3  | 1 2 [3]  <- was: ... 2 [3]
total=33   size=10  cur=1   n=2 | prev=false 1  next=true  2  | [1] 2 ...
total=33   size=10  cur=2   n=2 | prev=true  1  next=true  3  | 1 [2] 3 4  <- was: ... [2] 3 ...
total=33   size=10  cur=3   n=2 | prev=true  2  next=true  4  | ... [3] 4
total=33   size=10  cur=4   n=2 | prev=true  3  next=false 4  | ... 3 [4]
total=33   size=10  cur=5   n=2 | prev=true  3  next=false 4  | ... 3 [4]
total=43   size=10  cur=1   n=2 | prev=false 1  next=true  2  | [1] 2 ...
total=43   size=10  cur=2   n=2 | prev=true  1  next=true  3  | 1 [2] 3 ...  <- was: ... [2] 3 ...
total=43   size=10  cur=3   n=2 | prev=true  2  next=true  4  | ... [3] 4 5  <- was: ... [3] 4 ...
total=43   size=10  cur=4   n=2 | prev=true  3  next=true  5  | ... [4] 5
total=43   size=10  cur=5   n=2 | prev=true  4  next=false 5  | ... 4 [5]
total=43   size=10  cur=6   n=2 | prev=true  4  next=false 5  | ... 4 [5]
total=53   size=10  cur=1   n=2 | prev=false 1  next=true  2  | [1] 2 ...
total=53   size=10  cur=2   n=2 | prev=true  1  next=true  3  | 1 [2] 3 ...  <- was: ... [2] 3 ...
total=53   size=10  cur=3   n=2 | prev=true  2  next=true  4  | ... [3] 4 ...
total=53   size=10  cur=4   n=2 | prev=true  3  next=true  5  | ... [4] 5 6  <- was: ... [4] 5 ...
total=53   size=10  cur=5   n=2 | prev=true  4  next=true  6  | ... [5] 6
total=53   size=10  cur=6   n=2 | prev=true  5  next=false 6  | ... 5 [6]
total=53   size=10  cur=7   n=2 | prev=true  5  next=false 6  | ... 5 [6]
total=63   size=10  cur=1   n=2 | prev=false 1  next=true  2  | [1] 2 ...
total=63   size=10  cur=2   n=2 | prev=true  1  next=true  3  | 1 [2] 3 ...  <- was: ... [2] 3 ...
total=63   size=10  cur=3   n=2 | prev=true  2  next=true  4  | ... [3] 4 ...
total=63   size=10  cur=4   n=2 | prev=true  3  next=true  5  | ... [4] 5 ...
total=63   size=10  cur=5   n=2 | prev=true  4  next=true  6  | ... [5] 6 7  <- was: ... [5] 6 ...
total=63   size=10  cur=6   n=2 | prev=true  5  next=true  7  | ... [6] 7
total=63   size=10  cur=7   n=2 | prev=true  6  next=false 7  | ... 6 [7]
total=63   size=10  cur=8   n=2 | prev=true  6  next=false 7  | ... 6 [7]
total=73   size=10  cur=1   n=2 | prev=false 1  next=true  2  | [1] 2 ...
total=73   size=10  cur=2   n=2 | prev=true  1  next=true  3  | 1 [2] 3 ...  <- was: ... [2] 3 ...
total=73   size=10  cur=3   n=2 | prev=true  2  next=true  4  | ... [3] 4 ...
total=73   size=10  cur=4   n=2 | prev=true  3  next=true  5  | ... [4] 5 ...
total=73   size=10  cur=5   n=2 | prev=true  4  next=true  6  | ... [5] 6 ...
total=73   size=10  cur=6   n=2 | prev=true  5  next=true  7  | ... [6] 7 8  <- was: ... [6] 7 ...
total=73   size=10  cur=7   n=2 | prev=true  6  next=true  8  | ... [7] 8
total=73   size=10  cur=8   n=2 | prev=true  7  next=false 8  | ... 7 [8]
total=73   size=10  cur=9   n=2 | prev=true  7  next=false 8  | ... 7 [8]
total=0    size=10  cur=1   n=3 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=1   n=3 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=2   n=3 | prev=false 1  next=false 1  | [1]
total=13   size=10  cur=1   n=3 | prev=false 1  next=true  2  | [1] 2
total=13   size=10  cur=2   n=3 | prev=true  1  next=false 2  | 1 [2]
total=13   size=10  cur=3   n=3 | prev=true  1  next=false 2  | 1 [2]
total=23   size=10  cur=1   n=3 | prev=false 1  next=true  2  | [1] 2 3
total=23   size=10  cur=2   n=3 | prev=true  1  next=true  3  | 1 [2] 3
total=23   size=10  cur=3   n=3 | prev=true  2  next=false 3  | 1 2 [3]
total=23   size=10  cur=4   n=3 | prev=true  2  next=false 3  | 1 2 [3]
total=33   size=10  cur=1   n=3 | prev=false 1  next=true  2  | [1] 2 3 4  <- was: [1] 2 3 ...
total=33   size=10  cur=2   n=3 | prev=true  1  next=true  3  | 1 [2] 3 4  <- was: 1 [2] 3 ...
total=33   size=10  cur=3   n=3 | prev=true  2  next=true  4  | 1 2 [3] 4  <- was: ... 2 [3] 4
total=33   size=10  cur=4   n=3 | prev=true  3  next=false 4  | 1 2 3 [4]  <- was: ... 2 3 [4]
total=33   size=10  cur=5   n=3 | prev=true  3  next=false 4  | 1 2 3 [4]  <- was: ... 2 3 [4]
total=43   size=10  cur=1   n=3 | prev=false 1  next=true  2  | [1] 2 3 ...
total=43   size=10  cur=2   n=3 | prev=true  1  next=true  3  | 1 [2] 3 ...
total=43   size=10  cur=3   n=3 | prev=true  2  next=true  4  | 1 2 [3] 4 5  <- was: ... 2 [3] 4 ...
total=43   size=10  cur=4   n=3 | prev=true  3  next=true  5  | ... 3 [4] 5
total=43   size=10  cur=5   n=3 | prev=true  4  next=false 5  | ... 3 4 [5]
total=43   size=10  cur=6   n=3 | prev=true  4  next=false 5  | ... 3 4 [5]
total=53   size=10  cur=1   n=3 | prev=false 1  next=true  2  | [1] 2 3 ...
total=53   size=10  cur=2   n=3 | prev=true  1  next=true  3  | 1 [2] 3 ...
total=53   size=10  cur=3   n=3 | prev=true  2  next=true  4  | 1 2 [3] 4 ...  <- was: ... 2 [3] 4 ...
total=53   size=10  cur=4   n=3 | prev=true  3  next=true  5  | ... 3 [4] 5 6  <- was: ... 3 [4] 5 ...
total=53   size=10  cur=5   n=3 | prev=true  4  next=true  6  | ... 4 [5] 6
total=53   size=10  cur=6   n=3 | prev=true  5  next=false 6  | ... 4 5 [6]
total=53   size=10  cur=7   n=3 | prev=true  5  next=false 6  | ... 4 5 [6]
total=63   size=10  cur=1   n=3 | prev=false 1  next=true  2  | [1] 2 3 ...
total=63   size=10  cur=2   n=3 | prev=true  1  next=true  3  | 1 [2] 3 ...
total=63   size=10  cur=3   n=3 | prev=true  2  next=true  4  | 1 2 [3] 4 ...  <- was: ... 2 [3] 4 ...
total=63   size=10  cur=4   n=3 | prev=true  3  next=true  5  | ... 3 [4] 5 ...
total=63   size=10  cur=5   n=3 | prev=true  4  next=true  6  | ... 4 [5] 6 7  <- was: ... 4 [5] 6 ...
total=63   size=10  cur=6   n=3 | prev=true  5  next=true  7  | ... 5 [6] 7
total=63   size=10  cur=7   n=3 | prev=true  6  next=false 7  | ... 5 6 [7]
total=63   size=10  cur=8   n=3 | prev=true  6  next=false 7  | ... 5 6 [7]
total=73   size=10  cur=1   n=3 | prev=false 1  next=true  2  | [1] 2 3 ...
total=73   size=10  cur=2   n=3 | prev=true  1  next=true  3  | 1 [2] 3 ...
total=73   size=10  cur=3   n=3 | prev=true  2  next=true  4  | 1 2 [3] 4 ...  <- was: ... 2 [3] 4 ...
total=73   size=10  cur=4   n=3 | prev=true  3  next=true  5  | ... 3 [4] 5 ...
total=73   size=10  cur=5   n=3 | prev=true  4  next=true  6  | ... 4 [5] 6 ...
total=73   size=10  cur=6   n=3 | prev=true  5  next=true  7  | ... 5 [6] 7 8  <- was: ... 5 [6] 7 ...
total=73   size=10  cur=7   n=3 | prev=true  6  next=true  8  | ... 6 [7] 8
total=73   size=10  cur=8   n=3 | prev=true  7  next=false 8  | ... 6 7 [8]
total=73   size=10  cur=9   n=3 | prev=true  7  next=false 8  | ... 6 7 [8]
total=0    size=10  cur=1   n=4 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=1   n=4 | prev=false 1  next=false 1  | [1]
total=3    size=10  cur=2   n=4 | prev=false 1  next=false 1  | [1]
total=13   size=10  cur=1   n=4 | prev=false 1  next=true  2  | [1] 2
total=13   size=10  cur=2   n=4 | prev=true  1  next=false 2  | 1 [2]
total=13   size=10  cur=3   n=4 | prev=true  1  next=false 2  | 1 [2]
total=23   size=10  cur=1   n=4 | prev=false 1  next=true  2  | [1] 2 3
total=23   size=10  cur=2   n=4 | prev=true  1  next=true  3  | 1 [2] 3
total=23   size=10  cur=3   n=4 | prev=true  2  next=false 3  | 1 2 [3]
total=23   size=10  cur=4   n=4 | prev=true  2  next=false 3  | 1 2 [3]
total=33   size=10  cur=1   n=4 | prev=false 1  next=true  2  | [1] 2 3 4
total=33   size=10  cur=2   n=4 | prev=true  1  next=true  3  | 1 [2] 3 4
total=33   size=10  cur=3   n=4 | prev=true  2  next=true  4  | 1 2 [3] 4
total=33   size=10  cur=4   n=4 | prev=true  3  next=false 4  | 1 2 3 [4]
total=33   size=10  cur=5   n=4 | prev=true  3  next=false 4  | 1 2 3 [4]
total=43   size=10  cur=1   n=4 | prev=false 1  next=true  2  | [1] 2 3 4 5  <- was: [1] 2 3 4 ...
total=43   size=10  cur=2   n=4 | prev=true  1  next=true  3  | 1 [2] 3 4 5  <- was: 1 [2] 3 4 ...
total=43   size=10  cur=3   n=4 | prev=true  2  next=true  4  | 1 2 [3] 4 5  <- was: ... 2 [3] 4 5
total=43   size=10  cur=4   n=4 | prev=true  3  next=true  5  | 1 2 3 [4] 5  <- was: ... 2 3 [4] 5
total=43   size=10  cur=5   n=4 | prev=true  4  next=false 5  | 1 2 3 4 [5]  <- was: ... 2 3 4 [5]
total=43   size=10  cur=6   n=4 | prev=true  4  next=false 5  | 1 2 3 4 [5]  <- was: ... 2 3 4 [5]
total=53   size=10  cur=1   n=4 | prev=false 1  next=true  2  | [1] 2 3 4 ...
total=53   size=10  cur=2   n=4 | prev=true  1  next=true  3  | 1 [2] 3 4 ...
total=53   size=10  cur=3   n=4 | prev=true  2  next=true  4  | 1 2 [3] 4 5 6  <- was: ... 2 [3] 4 5 ...
total=53   size=10  cur=4   n=4 | prev=true  3  next=true  5  | ... 3 [4] 5 6
total=53   size=10  cur=5   n=4 | prev=true  4  next=true  6  | ... 3 4 [5] 6
total=53   size=10  cur=6   n=4 | prev=true  5  next=false 6  | ... 3 4 5 [6]
total=53   size=10  cur=7   n=4 | prev=true  5  next=false 6  | ... 3 4 5 [6]
total=63   size=10  cur=1   n=4 | prev=false 1  next=true  2  | [1] 2 3 4 ...
total=63   size=10  cur=2   n=4 | prev=true  1  next=true  3  | 1 [2] 3 4 ...
total=63   size=10  cur=3   n=4 | prev=true  2  next=true  4  | 1 2 [3] 4 5 ...  <- was: ... 2 [3] 4 5 ...
total=63   size=10  cur=4   n=4 | prev=true  3  next=true  5  | ... 3 [4] 5 6 7  <- was: ... 3 [4] 5 6 ...
total=63   size=10  cur=5   n=4 | prev=true  4  next=true  6  | ... 4 [5] 6 7
total=63   size=10  cur=6   n=4 | prev=true  5  next=true  7  | ... 4 5 [6] 7
total=63   size=10  cur=7   n=4 | prev=true  6  next=false 7  | ... 4 5 6 [7]
total=63   size=10  cur=8   n=4 | prev=true  6  next=false 7  | ... 4 5 6 [7]
total=73   size=10  cur=1   n=4 | prev=false 1  next=true  2  | [1] 2 3 4 ...
total=73   size=10  cur=2   n=4 | prev=true  1  next=true  3  | 1 [2] 3 4 ...
total=73   size=10  cur=3   n=4 | prev=true  2  next=true  4  | 1 2 [3] 4 5 ...  <- was: ... 2 [3] 4 5 ...
total=73   size=10  cur=4   n=4 | prev=true  3  next=true  5  | ... 3 [4] 5 6 ...
total=73   size=10  cur=5   n=4 | prev=true  4  next=true  6  | ... 4 [5] 6 7 8  <- was: ... 4 [5] 6 7 ...
total=73   size=10  cur=6   n=4 | prev=true  5  next=true  7  | ... 5 [6] 7 8
total=73   size=10  cur=7   n=4 | prev=true  6  next=true  8  | ... 5 6 [7] 8
total=73   size=10  cur=8   n=4 | prev=true  7  next=false 8  | ... 5 6 7 [8]
total=73   size=10  cur=9   n=4 | prev=true  7  next=false 8  | ... 5 6 7 [8]
# audit log page size 20
total=141  size=20  cur=1   n=5 | prev=false 1  next=true  2  | [1] 2 3 4 5 ...
total=141  size=20  cur=2   n=5 | prev=true  1  next=true  3  | 1 [2] 3 4 5 ...
total=141  size=20  cur=3   n=5 | prev=true  2  next=true  4  | 1 2 [3] 4 5 ...
total=141  size=20  cur=4   n=5 | prev=true  3  next=true  5  | 1 2 3 [4] 5 6 ...  <- was: ... 2 3 [4] 5 6 ...
total=141  size=20  cur=5   n=5 | prev=true  4  next=true  6  | ... 3 4 [5] 6 7 8  <- was: ... 3 4 [5] 6 7 ...
total=141  size=20  cur=6   n=5 | prev=true  5  next=true  7  | ... 4 5 [6] 7 8
total=141  size=20  cur=7   n=5 | prev=true  6  next=true  8  | ... 4 5 6 [7] 8
total=141  size=20  cur=8   n=5 | prev=true  7  next=false 8  | ... 4 5 6 7 [8]
`

// tableRow is one parsed row: the four arguments to New and the whole expected
// line, suffix removed.
type tableRow struct {
	total, size, cur, n int
	expected            string
}

func parseTable(t *testing.T) (rows []tableRow, marked int) {
	t.Helper()

	for _, line := range strings.Split(expectedTable, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		expected := line
		if before, _, found := strings.Cut(line, "  <- was:"); found {
			expected = before
			marked++
		}

		args, _, ok := strings.Cut(expected, "|")
		require.True(t, ok, "row has no field separator: %q", line)

		row := tableRow{expected: expected}
		for _, field := range strings.Fields(args) {
			name, value, ok := strings.Cut(field, "=")
			require.True(t, ok, "unparsable field %q in row %q", field, line)

			n, err := strconv.Atoi(value)
			require.NoError(t, err, "unparsable field %q in row %q", field, line)

			switch name {
			case "total":
				row.total = n
			case "size":
				row.size = n
			case "cur":
				row.cur = n
			case "n":
				row.n = n
			default:
				require.Failf(t, "unknown field", "%q in row %q", name, line)
			}
		}

		rows = append(rows, row)
	}

	return rows, marked
}

// format writes a Paginator back into the table's notation, so a failing row
// prints beside the row that produced it.
//
// The arms are ordered as partials/paginator.html orders its own: IsCurrent
// first, then the -1 sentinel. Testing Num == -1 first instead would print a
// sentinel that wrongly carried IsCurrent as plain "...", matching the table
// while the partial rendered it as an active "-1" button, so the notation would
// hide the one Page value the template can tell apart and the table cannot.
func format(row tableRow, p *Paginator) string {
	bar := make([]string, 0, len(p.Pages))
	for _, page := range p.Pages {
		switch {
		case page.IsCurrent:
			bar = append(bar, "["+strconv.Itoa(page.Num)+"]")
		case page.Num == -1:
			bar = append(bar, "...")
		default:
			bar = append(bar, strconv.Itoa(page.Num))
		}
	}

	return fmt.Sprintf("%-11s%-9s%-8sn=%d | prev=%-5t %-2d next=%-5t %-2d | %s",
		"total="+strconv.Itoa(row.total),
		"size="+strconv.Itoa(row.size),
		"cur="+strconv.Itoa(row.cur),
		row.n,
		p.HasPrevious, p.Previous, p.HasNext, p.Next,
		strings.Join(bar, " "))
}

func TestNew_Table(t *testing.T) {
	rows, _ := parseTable(t)

	for _, row := range rows {
		t.Run(fmt.Sprintf("total=%d_size=%d_cur=%d_n=%d", row.total, row.size, row.cur, row.n), func(t *testing.T) {
			assert.Equal(t, row.expected, format(row, New(row.total, row.size, row.cur, row.n)))
		})
	}
}

// TestNew_HugeTotalDoesNotOverflow pins the page count where the table cannot
// reach: a total within pageSize of the largest int. Computing the count as
// (total + pageSize - 1) / pageSize wraps there and the clamp turns the
// negative into a single page, so the bar would draw "[1]" alone over a result
// set with billions of pages in it.
//
// Only the page count is swept here. HasNext multiplies current by pageSize and
// that product still wraps on the last page of a MaxInt-sized total, which is
// what the library did too and what decision 3 keeps.
func TestNew_HugeTotalDoesNotOverflow(t *testing.T) {
	for _, size := range []int{10, 20} { // the two page sizes the handlers pass
		// The largest exact multiple of size, so the count is total/size with
		// nothing left over and current*size cannot wrap on the last page
		// either. Adding size-1 to it does wrap, which is the bug.
		total := math.MaxInt - math.MaxInt%size
		wantPages := total / size

		first := New(total, size, 1, 5)
		assert.Equal(t, []Page{{Num: 1, IsCurrent: true}, {Num: 2}, {Num: 3}, {Num: 4}, {Num: 5}, {Num: -1}}, first.Pages,
			"size=%d: five pages and an ellipsis, not a lone [1]", size)
		assert.True(t, first.HasNext, "size=%d: the forward arrow is live on page 1", size)

		// The clamp lands on the real last page rather than a wrapped one.
		last := New(total, size, math.MaxInt, 5)
		require.NotEmpty(t, last.Pages, "size=%d", size)
		assert.Equal(t, Page{Num: wantPages, IsCurrent: true}, last.Pages[len(last.Pages)-1],
			"size=%d: the last page is current", size)
		assert.True(t, last.HasPrevious, "size=%d: the back arrow is live on the last page", size)
		assert.False(t, last.HasNext, "size=%d: nothing follows the last page", size)
	}
}

// TestNew_TableIsComplete keeps the table from being trimmed into agreement
// with a broken New: a row deleted rather than fixed would otherwise pass.
func TestNew_TableIsComplete(t *testing.T) {
	rows, marked := parseTable(t)

	assert.Equal(t, 363, len(rows), "case rows in the table")
	assert.Equal(t, 73, marked, "rows where this package departs from the library it replaced")
}
