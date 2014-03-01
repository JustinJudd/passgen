package main

import (
	"fmt"
	"github.com/JustinJudd/cobra"
	"github.com/JustinJudd/passgen"
)

var (
	numFlag  int
	minFlag  int
	maxFlag  int
	wordFlag int

	typeFlag string
	dictFlag string
)

func main() {

	var rootCmd = &cobra.Command{
		Use:   "passgen",
		Short: "passgen is a password and passphrase creation utility.",
		Long:  "passgen allows you to create secure passwords and passphrases.",
	}
	var passwordCmd = &cobra.Command{
		Use:   "password",
		Short: "password allows for a password to be generated.",
		Long:  "password allows you to create secure passwords.",
		Run: func(cmd *cobra.Command, args []string) {
			var gen *passgen.PasswordGenerator
			switch typeFlag {

			case "secure", "s":
				gen = passgen.GetSecurePasswordGenerator()
			case "numeric", "n":
				gen = passgen.GetNumericPasswordGenerator()
			case "alphanumeric", "a":
				gen = passgen.GetAlphaNumericPasswordGenerator()
			default:
				println("Unknown password type")
				return

			}
			for i := 0; i < numFlag; i++ {
				p, err := gen.GeneratePassword(minFlag, maxFlag)
				if err != nil {
					fmt.Println("Error generating password")
				}
				fmt.Println(p)
			}

		},
	}
	var passphraseCmd = &cobra.Command{
		Use:   "passphrase",
		Short: "passphrase allows for a passphrase to be generated.",
		Long:  "passphrase allows you to create secure passphrases.",
		Run: func(cmd *cobra.Command, args []string) {
			gen, err := passgen.NewPassphraseGenerator(dictFlag, minFlag, maxFlag)
			if err != nil {
				println("Unable to create passphrase generator")
				return
			}
			for i := 0; i < numFlag; i++ {
				p := gen.GeneratePassphrase(wordFlag)

				fmt.Println(p)
			}
		},
	}

	passwordCmd.Flags().IntVarP(&numFlag, "num", "n", 1, "number of passwords to generate")
	passwordCmd.Flags().IntVarP(&minFlag, "min", "m", 8, "minimum length of generated password")
	passwordCmd.Flags().IntVarP(&maxFlag, "max", "x", 14, "maximum length of generated password")
	passwordCmd.Flags().StringVarP(&typeFlag, "type", "t", "secure", "type of password to generate. Options are (s)ecure, (a)lphanumeric, and (n)umeric")

	passphraseCmd.Flags().IntVarP(&numFlag, "num", "n", 1, "number of passphrases to generate")
	passphraseCmd.Flags().IntVarP(&wordFlag, "words", "w", 4, "number of words that the passphrase should contain")
	passphraseCmd.Flags().IntVarP(&minFlag, "min", "m", 4, "minimum length of words to allow")
	passphraseCmd.Flags().IntVarP(&maxFlag, "max", "x", 10, "maximum length of words to allow")
	passphraseCmd.Flags().StringVarP(&dictFlag, "dict", "d", "internal", "dictionary file to use to find words. Uses an internal list by default")

	rootCmd.AddCommand(passwordCmd, passphraseCmd)

	err := rootCmd.Execute()
	if err != nil {
		println("Error starting passgen")
	}
	return

	p, err := passgen.GetXKCDPassphrase(4)
	if err != nil {
		fmt.Println("Error generating passphrase")
	}
	fmt.Println(p)

	p, err = passgen.GetNumericPassword(4, 4)
	if err != nil {
		fmt.Println("Error generating password")
	}
	fmt.Println(p)

	p, err = passgen.GetSecurePassword(14, 40)
	if err != nil {
		fmt.Println("Error generating password")
	}
	fmt.Println(p)
}
