package main

import "os"

var PREFIX = "/usr"
var DOCSFILES = []string{"LICENSE", "README.md", "TODO.md"}

func init() {
	if p := os.Getenv("PREFIX"); p != "" {
		PREFIX = p
	}
}
