package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/binaryfigments/emaildefense"
)

func main() {
	hostname := strings.ToLower(os.Args[1])
	nameserver := strings.ToLower(os.Args[2])
	fullarg := strings.ToLower(os.Args[3])
	var full bool
	if fullarg == "true" {
		full = true
	} else {
		full = false
	}

	caadata := emaildefense.Get(hostname, nameserver, full)

	json, err := json.MarshalIndent(caadata, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", json)
}
