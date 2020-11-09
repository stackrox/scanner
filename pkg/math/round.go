package math

import "math"

// RoundTo1Decimal returns the given float64 rounded to the nearest tenth place.
func RoundTo1Decimal(x float64) float64 {
	return math.Round(x*10) / 10
}
