package util

const (
	AZN = "AZN"
	USD = "USD"
	EUR = "EUR"
)

func IsSupportedCurrency(currency string) bool {
	switch currency {
	case AZN, USD, EUR:
		return true
	}
	return false
}
