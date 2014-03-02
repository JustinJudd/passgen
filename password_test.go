package passgen

import (
	"fmt"
	"strings"
	"testing"
)

func TestGetPassword(t *testing.T) {
	p, err := GetNumericPassword(14, 20)
	if err != nil {
		t.Fatal("Error generating password", err)
	}
	if len(p) > 20 || len(p) < 14 {
		t.Error("Incorrect sized password returned")
	}
}

func TestGetPasswordSameSize(t *testing.T) {
	p, err := GetNumericPassword(4, 4)
	if err != nil {
		t.Fatal("Error generating password", err)
	}
	if len(p) != 4 {
		t.Error("Incorrect sized password returned")
	}
}

func TestGetPasswordOddSize(t *testing.T) {
	p, err := GetNumericPassword(15, 15)
	if err != nil {
		t.Fatal("Error generating password", err)
	}
	if len(p) != 15 {
		t.Error("Incorrect sized password returned")
	}
}

var digits = "1234567890"

func TestGetNumericPassword(t *testing.T) {
	p, err := GetNumericPassword(14, 20)
	if err != nil {
		t.Fatal("Error generating password", err)
	}
	for _, c := range p {
		if !strings.ContainsRune(digits, c) {
			t.Errorf("Invalid character found: %c (%x)", c, c)
			break
		}
	}
}

var alpha_lower = "abcdefghijklmnopqrstuvwxyz"

func TestGetAlphaLowerPassword(t *testing.T) {
	p, err := GetAlphaLowerPassword(14, 20)
	if err != nil {
		t.Fatal("Error generating password", err)
	}
	for _, c := range p {
		if !strings.ContainsRune(alpha_lower, c) {
			t.Errorf("Invalid character found: %c (%x)", c, c)
			break
		}
	}
}

var alpha_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

func TestGetAlphaUpperPassword(t *testing.T) {
	p, err := GetAlphaUpperPassword(14, 20)
	if err != nil {
		t.Fatal("Error generating password", err)
	}
	for _, c := range p {
		if !strings.ContainsRune(alpha_upper, c) {
			t.Errorf("Invalid character found: %c (%x)", c, c)
			break
		}
	}
}

func TestGetAlphaPassword(t *testing.T) {
	p, err := GetAlphaPassword(14, 20)
	if err != nil {
		t.Fatal("Error generating password", err)
	}
	for _, c := range p {
		if !strings.ContainsRune(alpha_upper+alpha_lower, c) {
			t.Errorf("Invalid character found: %c (%x)", c, c)
			break
		}
	}
}

var symbols = " !@#$%^&*()`~-_=+[{]}\\|,<.>/?;:'\""

func TestGetSecurePassword(t *testing.T) {
	p, err := GetSecurePassword(14, 20)
	if err != nil {
		t.Fatal("Error generating password", err)
	}
	for _, c := range p {
		if !strings.ContainsRune(alpha_upper+alpha_lower+symbols+digits, c) {
			t.Errorf("Invalid character found: %c (%x)", c, c)
			break
		}
	}
}

func TestGetLargePassword(t *testing.T) {
	p, err := GetSecurePassword(40, 200)
	if err != nil {
		t.Fatal("Error generating password", err)
	}
	if len(p) > 200 || len(p) < 40 {
		t.Error("Incorrect sized password returned")
	}
	for _, c := range p {
		if !strings.ContainsRune(alpha_upper+alpha_lower+symbols+digits, c) {
			t.Errorf("Invalid character found: %c (%x)", c, c)
			break
		}
	}
}

func TestGetLargeNumericPassword(t *testing.T) {
	p, err := GetNumericPassword(40, 200)
	if err != nil {
		t.Fatal("Error generating password", err)
	}
	if len(p) > 200 || len(p) < 40 {
		t.Error("Incorrect sized password returned")
	}
	for _, c := range p {
		if !strings.ContainsRune(digits, c) {
			t.Errorf("Invalid character found: %c (%x)", c, c)
			break
		}
	}
}
func TestPasswordGenerator(t *testing.T) {
	gen := GetSecurePasswordGenerator()
	for i := 0; i < 5; i++ {
		p, err := gen.GeneratePassword(14, 20)
		if err != nil {
			t.Fatal("Error generating password", err)
		}
		if len(p) > 20 || len(p) < 14 {
			t.Error("Incorrect sized password returned")
		}
		for _, c := range p {
			if !strings.ContainsRune(alpha_upper+alpha_lower+symbols+digits, c) {
				t.Errorf("Invalid character found: %c", c)
				break
			}
		}
	}

}

func TestGetPasswordBias(t *testing.T) {
	N := 10000000
	var freq [10]map[rune]int
	for i := 0; i < 10; i++ {
		freq[i] = make(map[rune]int)
	}
	for i := 0; i < N; i++ {
		p, err := GetNumericPassword(10, 10)
		if err != nil {
			t.Fatal("Error generating password", err)
		}
		if len(p) != 10 {
			t.Error("Incorrect sized password returned")
		}
		for j, c := range p {
			if _, ok := freq[j][c]; ok {
				freq[j][c]++
			} else {
				freq[j][c] = 1
			}
		}
	}
	for i := 0; i < 10; i++ {
		for _, c := range "0123456789" {
			cnt := freq[i][c]
			fmt.Printf("'%c' %5.2f ", c, 100*(float64(cnt)/float64(N))-10.0)
		}
		fmt.Println()
	}
	t.Fatal("")
}
