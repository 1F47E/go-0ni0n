// parsing tor Directory Authorities and get the list of tor root nodes
// then parse the list of nodes
package main

import (
	"fmt"
	"log"
)

func main() {
	dirs, err := Parse()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Found %d auth dirs\n", len(dirs))
	for _, auth := range dirs {
		fmt.Println(auth)
	}
}
