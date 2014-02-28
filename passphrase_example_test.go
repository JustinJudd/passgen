package passgen


import (
	"fmt"
)

func ExampleGetXKCDPassphrase() {
	p, err := GetXKCDPassphrase(4)
	if err != nil {
		//handle error
	}
	fmt.Println(p)
}

func ExamplePassphraseGenerator() {
	// Can use any PassphraseGenerator - provided or Custom
	gen, err := GetXKCDPassphraseGenerator()
	if err != nil {
		// Handle error
	}
	for i:=0; i<5; i++ {
		p := gen.GeneratePassphrase(4)
		fmt.Println(p)
	}
}

func ExampleNewPassphraseGenerator() {
	// This example will create a passphrase generator that will use 6 short words, 2 to 4 letter words, from the internal dictionary
	gen, err := NewPassphraseGenerator("internal", 2, 4)
	if err != nil {
		// Handle error
	}
	for i:=0; i<5; i++ {
		p := gen.GeneratePassphrase(6)
		fmt.Println(p)
	}
}

func ExampleNewPassphraseGenerator_dictionaryFile() {
	// This example will create a passphrase generator that will use a custom dictionary file for finding words
	gen, err := NewPassphraseGenerator("path/to/dictioanry", 4, 8)
	if err != nil {
		// Handle error
	}
	for i:=0; i<5; i++ {
		p := gen.GeneratePassphrase(4)
		fmt.Println(p)
	}
}

