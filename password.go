/*
Package passgen allows for creating passwords and passphrases.
Custom generators can be created to allow easy, full control of the types of passwords and passphrases generated
*/
package passgen

import (
	"crypto/rand"
	"errors"
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
		l, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
		if err != nil {
			return "", errors.New("Unable to generate random length")
		}
		length = int(l.Int64()) + min
	}

	b := make([]byte, max)
	_, err := rand.Read(b)
	if err != nil {
		return "", errors.New("Unable to generate random data")
	}

	buf := make([]byte, p.GetMaxLength(len(b)))
	p.generatePassword(buf, []byte(b))
	return string(buf[0:length]), nil

}

// Get a new Password Generator designed to start at the given starting character and use the given character space
func NewPasswordGenerator(start byte, size int) *PasswordGenerator {
	p := &PasswordGenerator{CharStart: start, CharLen: size}

	// How many characters in the given character space can be drawn from a 32-bit value?
	for i := 2; i < 32; i++ {
		if math.Pow(float64(p.CharLen), float64(i)) > math.MaxInt32 {
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
	return (n + p.rounds - 1) / 4 * p.rounds
}

// Generate the password
// Takes a random byte slice as the source and destination is a byte slice of the random data represented in the chosen character space
// Returns the number of bytes in the destination byte slice
// Modeled after ASCII-85 Encode
func (p *PasswordGenerator) generatePassword(dst, src []byte) int {
	if len(src) == 0 {
		return 0
	}

	n := 0
	for len(src) > 0 {
		for i := 0; i < p.rounds; i++ {
			dst[i] = 0
		}

		// Unpack 4 bytes into uint32 to repack/encode into desired character set.
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

		// Loop through how ever many rounds we can get unique data from 32-bits of data
		for i := p.rounds - 1; i >= 0; i-- {
			if p.Func != nil {
				dst[i] = p.Func(v % uint32(p.CharLen))
			} else {
				dst[i] = p.CharStart + byte(v%uint32(p.CharLen))
			}

			v /= uint32(p.CharLen)
		}

		// If src was short, discard the low destination bytes.
		m := p.rounds
		if len(src) < p.rounds-1 {
			m -= p.rounds - 1 - len(src)
			src = nil
		} else {
			src = src[p.rounds:]
		}
		dst = dst[m:]
		n += m
	}
	return n
}
