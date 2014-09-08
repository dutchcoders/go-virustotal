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

	apikey := flag.String("apikey", os.GetEnv("VIRUSTOTAL_APIKEY"), "the api key of virustotal")
	debug := flag.Bool("debug", false, "debug")

	flag.Parse()

	if *apikey == "" {
		fmt.Println("API key not set")
		return
	}

	vt, err := virustotal.NewVirusTotal(*apikey)
	if err != nil {
		log.Fatal(err)
	}

        if flag.Arg(0) == "scan" {
            for _, path := range flag.Args()[1:] {
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

                    if (*debug) {
                        fmt.Println(result)
                    }
            }
        } else if flag.Arg(0) == "rescan" {
            result, err := vt.Rescan(flag.Args()[1:])

            if err != nil {
                    log.Fatal(err)
            }

            fmt.Printf("%s\n", result.Message)

            if (*debug) {
                fmt.Println(result)
            }
        } else if flag.Arg(0) == "ipaddress" {
            result, err := vt.IpAddressReport(flag.Args()[1])

            if err != nil {
                    log.Fatal(err)
            }

            fmt.Printf("%s\n", result.Message)

            if (*debug) {
                fmt.Println(result)
            }
        } else if flag.Arg(0) == "domain" {
            result, err := vt.DomainReport(flag.Args()[1])

            if err != nil {
                    log.Fatal(err)
            }

            fmt.Printf("%s\n", result.Message)

            if (*debug) {
                fmt.Println(result)
            }
        } else {
            fmt.Println("Usage:")
            fmt.Println("")
            fmt.Println("go run ./bin/vt.go --apikey {key} scan {file} {file} ...")
            fmt.Println("go run ./bin/vt.go --apikey {key} rescan {hash} {hash} ...")
            fmt.Println("go run ./bin/vt.go --apikey {key} ipaddress 90.156.201.27")
        }            

}
