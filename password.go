/*
Package passgen allows for creating passwords and passphrases.
Custom generators can be created to allow easy, full control of the types of passwords and passphrases generated
*/
package passgen

import (
	"crypto/rand"
	"errors"
	"io"
	"math"
	"math/big"
)

// Get a secure password between min and max characters long
func GetSecurePassword(min, max int) (string, error) {
	gen := GetSecurePasswordGenerator()
	return gen.GeneratePassword(min, max)

}

// Get a numeric password between min and max characters long
func GetNumericPassword(min, max int) (string, error) {
	gen := GetNumericPasswordGenerator()
	return gen.GeneratePassword(min, max)

}

// Get an alphanumeric password between min and max characters long
func GetAlphaNumericPassword(min, max int) (string, error) {
	gen := GetAlphaNumericPasswordGenerator()
	return gen.GeneratePassword(min, max)

}

// Get an alphabetic password between min and max characters long
func GetAlphaPassword(min, max int) (string, error) {
	gen := GetAlphaPasswordGenerator()
	return gen.GeneratePassword(min, max)

}

// Get a lowercase alphabetic password between min and max characters long
func GetAlphaLowerPassword(min, max int) (string, error) {
	gen := GetAlphaLowerPasswordGenerator()
	return gen.GeneratePassword(min, max)

}

// Get an uppercase alphabetic password between min and max characters long
func GetAlphaUpperPassword(min, max int) (string, error) {
	gen := GetAlphaUpperPasswordGenerator()
	return gen.GeneratePassword(min, max)

}

// Password Generator is used to generate passwords according to it's settings/properties.
// The generator can indefinitely be used to generate passwords.
type PasswordGenerator struct {
	// The ASCII Character to start pulling allowable password characters at
	CharStart byte
	// The number of Characters to be used for the password space
	CharLen int

	// Function to map a number to the ASCII character that should represent it
	Func func(i uint32) byte

	rounds int
}

// Use the generator to create a password in between the given lengths
func (p *PasswordGenerator) GeneratePassword(min, max int) (string, error) {
	length := min
	if min != max {
		l, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)+1))
		if err != nil {
			return "", errors.New("Unable to generate random length")
		}
		length = int(l.Int64()) + min
	}

	buf := make([]byte, p.GetMaxLength(max))
	n := p.generatePassword(buf, rand.Reader)
	//n := p.generatePassword2(buf)
	if n < length {
		return "", errors.New("Didn't generate enough random data")
	}
	return string(buf[0:length]), nil

}

// Get a new Password Generator designed to start at the given starting character and use the given character space
func NewPasswordGenerator(start byte, size int) *PasswordGenerator {
	p := &PasswordGenerator{CharStart: start, CharLen: size}

	// How many characters in the given character space can be drawn from a 32-bit value?
	for i := 2; i < 32; i++ {
		if math.Pow(float64(p.CharLen), float64(i)) > math.MaxUint32 {
			p.rounds = i - 1
			break
		}
	}
	return p

}

//Get a Password Generator that will allow ASCII x20-x7E   - 95 characters
func GetSecurePasswordGenerator() *PasswordGenerator {
	p := NewPasswordGenerator(' ', 95)
	return p
}

// Get a Password Generator that will only allow alphanumeric characters.
// (A-Za-z0-9) - 62 characters
func GetAlphaNumericPasswordGenerator() *PasswordGenerator {
	p := NewPasswordGenerator('0', 62)
	p.Func = func(i uint32) byte {
		switch {
		case i < 10:
			return '0' + byte(i)
		case i >= 36:
			return 'a' + byte(i) - 36
		default:
			return 'A' + byte(i) - 10
		}

	}
	return p
}

// Get a Password Generator that will only allow numeric characters.
// (0-9) - 10 characters
func GetNumericPasswordGenerator() *PasswordGenerator {
	p := NewPasswordGenerator('0', 10)
	return p
}

// Get a Password Generator that will only allow alphabetic characters.
// (A-Za-z) - 52 characters
func GetAlphaPasswordGenerator() *PasswordGenerator {
	p := NewPasswordGenerator('A', 52)
	p.Func = func(i uint32) byte {
		switch {
		case i < 26:
			return 'A' + byte(i)
		default:
			return 'a' + byte(i) - 26
		}

	}
	return p
}

// Get a Password Generator that will only allow upper case alphabetic characters.
// (A-Z) - 26 characters
func GetAlphaUpperPasswordGenerator() *PasswordGenerator {
	p := NewPasswordGenerator('A', 26)
	return p
}

// Get a Password Generator that will only allow lower case alphabetic characters.
// (a-z) - 26 characters
func GetAlphaLowerPasswordGenerator() *PasswordGenerator {
	p := NewPasswordGenerator('a', 26)
	return p
}

// Get the maximum length in bytes that the generated password might need
func (p *PasswordGenerator) GetMaxLength(n int) int {
	l := (n + p.rounds + 1) / 4 * p.rounds
	if l > n {
		return l
	}
	return n
}

// Generate the password
// Takes a random byte slice as the source and destination is a byte slice of the random data represented in the chosen character space
// Returns the number of bytes in the destination byte slice
// Hybrid model based on ASCII-85 Encode and crypto rand.Int
func (p *PasswordGenerator) generatePassword(dst []byte, rand io.Reader) int {
	if rand == nil {
		return 0
	}

	n := 0
	total := len(dst)
	var bias uint32
	t := uint32(math.Pow(float64(p.CharLen), float64(p.rounds)))
	d := math.MaxUint32 / t
	bias = t * d

	for total > n {

		src := make([]byte, 4)
		nb, err := rand.Read(src)
		if err != nil || len(src) != 4 {
			println("Unable to fill src with random data", len(src), nb)
		}

		// Unpack 4 bytes into uint32.
		var v uint32
		switch len(src) {
		default:
			v |= uint32(src[3])
			fallthrough
		case 3:
			v |= uint32(src[2]) << 8
			fallthrough
		case 2:
			v |= uint32(src[1]) << 16
			fallthrough
		case 1:
			v |= uint32(src[0]) << 24
		}

		if v >= bias {
			// doesn't pass bias check. Get the next set of random data
			continue
		}

		// Determine how many rounds we can run
		rounds := p.rounds
		if len(dst) < p.rounds {
			rounds = len(dst)
		}
		for i := 0; i < rounds; i++ {
			dst[i] = 0
		}

		// Loop through how ever many rounds we can get unique data from 32-bits of data
		for i := 0; i < rounds; i++ {
			next := v % uint32(p.CharLen)
			if p.Func != nil {
				dst[i] = p.Func(next)
			} else {
				dst[i] = p.CharStart + byte(next)
			}

			v /= uint32(p.CharLen)
		}

		dst = dst[rounds:]
		n += rounds
	}
	return n
}

// A secondary password generator using crypto/rand.Int for random data
func (p *PasswordGenerator) generatePassword2(dst []byte) int {
	for i := range dst {
		next, _ := rand.Int(rand.Reader, big.NewInt(int64(p.CharLen)))
		if p.Func != nil {
			dst[i] = p.Func(uint32(next.Int64()))
		} else {
			dst[i] = p.CharStart + byte(uint32(next.Int64()))
		}
	}
	return len(dst)
}
