package passgen

import (
	"testing"
	"strings"
)


func TestGetPassphrase(t *testing.T) {

	p, err := GetXKCDPassphrase(4)
	if err != nil {
		t.Fatal("Error generating passphrase", err)
	}
	s := strings.Split(p, " ")
	if len(s) != 4 {
		t.Error("Incorrect sized password returned. Expected: %d\t Actual: %d", 4, len(s))
	}
	for _, w := range s {
		if len(w)>10 || len(w)<4 {
			t.Error("A word was not within the correct wordlength range")
		}
	}
}



func TestPassphraseGenerator(t *testing.T) {
	gen, err := GetXKCDPassphraseGenerator()
	if err != nil {
		t.Fatal("Error generating passphrase generator", err)
	}
	for i:=0; i<5; i++ {
		p := gen.GeneratePassphrase(4)
		
		s := strings.Split(p, " ")
		if len(s) != 4 {
			t.Errorf("Incorrect sized password returned. Expected: %d\t Actual: %d", 4, len(s))
		}
		for _, w := range s {
			if len(w)>10 || len(w)<4 {
				t.Error("A word was not within the correct wordlength range")
			}
		}
	}
	
}


func TestCustomPassphraseGenerator(t *testing.T) {
	gen, err := NewPassphraseGenerator("internal", 5,8)
	if err != nil {
		t.Fatal("Error generating passphrase generator", err)
	}
	for i:=0; i<5; i++ {
		p:= gen.GeneratePassphrase(4)
		
		s := strings.Split(p, " ")
		if len(s) != 4 {
			t.Errorf("Incorrect sized password returned. Expected: %d\t Actual: %d", 4, len(s))
		}
		for _, w := range s {
			if len(w)>8 || len(w)<5 {
				t.Error("A word was not within the correct wordlength range")
			}
		}
	}
	
}

