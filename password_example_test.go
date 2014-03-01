package passgen

import (
	"fmt"
)

func ExampleGetNumericPassword() {
	p, err := GetNumericPassword(14, 20)
	if err != nil {
		//handle error
	}
	fmt.Println(p)
}

func ExampleGetSecurePassword() {
	p, err := GetSecurePassword(14, 20)
	if err != nil {
		//handle error
	}
	fmt.Println(p)
}

func ExampleGetAlphaNumericPassword() {
	p, err := GetAlphaNumericPassword(14, 20)
	if err != nil {
		//handle error
	}
	fmt.Println(p)
}

func ExampleGetAlphaLowerPassword() {
	p, err := GetAlphaLowerPassword(14, 20)
	if err != nil {
		//handle error
	}
	fmt.Println(p)
}

func ExampleGetAlphaUpperPassword() {
	p, err := GetAlphaUpperPassword(14, 20)
	if err != nil {
		//handle error
	}
	fmt.Println(p)
}

func ExamplePasswordGenerator() {
	// Can use any PasswordGenerator - In this example, a SecurePasswordGenerator
	gen := GetSecurePasswordGenerator()
	for i := 0; i < 5; i++ {
		p, err := gen.GeneratePassword(14, 20)
		if err != nil {
			//handle error
		}
		fmt.Println(p)
	}
}

func ExampleNewPasswordGenerator() {
	// Make a password generator that will only return passwords containing chars a-e
	gen := NewPasswordGenerator('a', 5)

	// Can now use the generator to create as many passwords as needed
	for i := 0; i < 5; i++ {
		p, err := gen.GeneratePassword(14, 20)
		if err != nil {
			//handle error
		}
		fmt.Println(p)
	}
}

func ExampleNewPasswordGenerator_custom() {
	// Make a password generator that will only return passwords containing chars of even numbers
	gen := NewPasswordGenerator('0', 5)
	gen.Func = func(i uint32) byte {
		diff := i * 2
		return gen.CharStart + byte(diff)
	}

	// Can now use the generator to create as many passwords as needed
	for i := 0; i < 5; i++ {
		p, err := gen.GeneratePassword(14, 20)
		if err != nil {
			//handle error
		}
		fmt.Println(p)
	}
}
