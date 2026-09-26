// SPDX-License-Identifier: Apache-2.0

package store

import (
	"math"

	"github.com/yamatrireddy/kilnci/server/internal/domain"
)

// int32Of converts n for an int4 column, failing with a validation error
// instead of silently wrapping when it does not fit.
func int32Of(field string, n int64) (int32, error) {
	if n < math.MinInt32 || n > math.MaxInt32 {
		return 0, domain.NewValidationError(field, "is out of range")
	}
	return int32(n), nil
}
