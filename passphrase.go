package passgen

import (
	"bufio"
	"crypto/rand"
	"math/big"
	"os"
	"strings"

	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/gob"
	"errors"
)

// Quickly get a Passphrase according to XKCD example(http://xkcd.com/936/)
func GetXKCDPassphrase(numWords int) (string, error) {
	gen, err := GetXKCDPassphraseGenerator()
	if err != nil {
		return "", err
	}
	return gen.GeneratePassphrase(numWords), nil
}

// Generate a Passphrase using the configuration options of the Passphrase Generator
func (p *PassphraseGenerator) GeneratePassphrase(numWords int) string {
	words := make([]string, numWords)
	l := big.NewInt(int64(len(p.dict)))
	for i := 0; i < numWords; i++ {
		// Randomly choose an index for a word from the dictionary
		n, _ := rand.Int(rand.Reader, l)
		words[i] = p.dict[n.Int64()]
	}
	// Collapse all of the chosen words into a string
	return strings.Join(words, " ")
}

// Get a Passphrase Generator that exceeds the XKCD example (http://xkcd.com/936/).
// Creates a Passphrase Generator that chooses 4 words of between 4 to 10 characters long
func GetXKCDPassphraseGenerator() (*PassphraseGenerator, error) {
	p, err := NewPassphraseGenerator("internal", 5, 8)
	return p, err
}

// Create a new Passphrase Generator. Use "internal" for the dictfile to use an internal list of words
func NewPassphraseGenerator(dictFile string, min, max int) (*PassphraseGenerator, error) {
	p := &PassphraseGenerator{MinWordLength: min, MaxWordLength: max, DictionaryFile: dictFile}
	var err error
	switch dictFile {
	case "internal":
		err = p.loadMemoryDict()
		if err != nil {
			err = errors.New("Unable to load internal memory")
		}
	default:
		err = p.loadDict()
		if err != nil {
			err = errors.New("Unable to load dictionary file")
		}
	}
	return p, err
}

func (p *PassphraseGenerator) loadMemoryDict() error {
	var dict []string
	b, err := base64.StdEncoding.DecodeString(dictStored)
	if err != nil {
		return errors.New("Unable to decode internal dictionary")
	}
	buf := bytes.NewBuffer(b)
	z, err := gzip.NewReader(buf)
	if err != nil {
		return errors.New("Unable to decompress internal dictionary")
	}
	defer z.Close()
	enc := gob.NewDecoder(z)
	err = enc.Decode(&dict)
	if err != nil {
		return errors.New("Unable to decode internal dictionary")
	}
	for _, line := range dict {
		if len(line) >= p.MinWordLength && len(line) <= p.MaxWordLength {
			p.dict = append(p.dict, line)
		}
	}
	return nil
}

// Load a Dictionary File referenced in the Passphrase Generator.
// Extract all words that meet the requirements in the Generator config
func (p *PassphraseGenerator) loadDict() error {
	file, err := os.Open(p.DictionaryFile)
	if err != nil {
		return errors.New("Unable to open dictionary file")
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) >= p.MinWordLength && len(line) <= p.MaxWordLength {
			p.dict = append(p.dict, line)
		}
	}
	return nil

}

// Passphrase Generator is used to generate secure passphrases
// Can be reused to generate as many sequential passphrases as desired
type PassphraseGenerator struct {
	// Path of the Dictionary file to extract words from
	DictionaryFile string

	// Minimumum and Maximum word lengths of words that should be allowed in the passphrase
	MinWordLength, MaxWordLength int

	// An internal slice of allowed words
	dict []string
}
