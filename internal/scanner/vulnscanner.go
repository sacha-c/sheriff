package scanner

// VulnScanner is an interface for any vulnerability scanner
type VulnScanner[T any] interface {
	// Scan runs a vulnerability scan on the given directory
	Scan(dir string) (*T, error)
}
