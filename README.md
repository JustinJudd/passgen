passgen
=======

A password and passphrase generation library and utility.
Passgen includes a builtin dictionary so you can get up and running, but you can replace it if you need.

There are two parts to this, a go library that can easily be imported and used, and a command utility.

passgen CLI
===========

Install
-------
### Getting passgen
There are two ways to install passgen. Binaries will be linked here, or you can build it yourself.

#### Building passgen
    $ go get github.com/JustinJudd/passgen/passgen
  
###  Using passgen

You can view a full list of commands using `$ passgen help` and `$ passgen help [command]` but the following examples cover most use cases

Generate a password with

    $ passgen password
    
Generate a numeric password (just numbers) of 4 characters

    $ passgen password --type n --min=4 --max=4

Generate a passphrase with  

    $ passgen passphrase
    
Provide a custom dictionary file for the passphrase

    $ passgen passphrase -d /usr/share/dict/dict.txt


    
passgen Library
===============

Full documentation for the library is found at [GoDoc](https://godoc.org/github.com/JustinJudd/passgen), including examples





