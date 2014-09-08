package main

import (
	"flag"
	"fmt"
	"github.com/dutchcoders/go-virustotal"
	"log"
	"os"
)

func main() {
	fmt.Println("go-virustotal: golang implementation of virustotal api")
	fmt.Println("")
	fmt.Println("Made with <3 by DutchCoders (http://dutchcoders.io/)")
	fmt.Println("----------------------------------------------------")

	apikey := flag.String("apikey", "", "the api key of virustotal")

	flag.Parse()

	fmt.Println("Usage:")
	fmt.Println("go run ./bin/vt.go --apikey {key} {file} {file} ...")
	if *apikey == "" {
		fmt.Println("API key not set")
		return
	}

	vt, err := virustotal.NewVirusTotal(*apikey)
	if err != nil {
		log.Fatal(err)
	}

	for _, path := range flag.Args() {
		fmt.Printf("Uploading %s to VirusTotal: ", path)

		file, err := os.Open(path)

		if err != nil {
			log.Fatal(err)
		}

		defer file.Close()

		result, err := vt.Scan(path, file)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s\n", result.Message)
	}
}
