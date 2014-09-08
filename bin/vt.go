/*
Open Source Initiative OSI - The MIT License (MIT):Licensing

The MIT License (MIT)
Copyright (c) 2013 DutchCoders <http://github.com/dutchcoders/>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"flag"
	"fmt"
	"github.com/dutchcoders/go-virustotal"
	"log"
	"net/url"
	"os"
)

func main() {
	fmt.Println("go-virustotal: golang implementation of virustotal api")
	fmt.Println("")
	fmt.Println("Made with <3 by DutchCoders (http://dutchcoders.io/)")
	fmt.Println("----------------------------------------------------")

	apikey := flag.String("apikey", os.Getenv("VIRUSTOTAL_APIKEY"), "the api key of virustotal")
	resource := flag.String("resource", "", "the api key of virustotal")
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
			var result *virustotal.ScanResponse

			// not an url
			fmt.Printf("Uploading %s to VirusTotal: ", path)

			file, err := os.Open(path)

			if err != nil {
				log.Fatal(err)
			}

			defer file.Close()

			result, err = vt.Scan(path, file)

			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("%s\n", result.Message)

			if *debug {
				fmt.Println(result)
			}
		}
	} else if flag.Arg(0) == "scan-url" {
		for _, path := range flag.Args()[1:] {
			u, err := url.Parse(path)

			var result *virustotal.ScanResponse

			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("Sending %s to VirusTotal: ", u.String())

			result, err = vt.ScanUrl(u)

			if err != nil {
				log.Fatal(err)
			}

			fmt.Printf("%s\n", result.Message)

			if *debug {
				fmt.Println(result)
			}
		}
	} else if flag.Arg(0) == "rescan" {
		result, err := vt.Rescan(flag.Args()[1:])

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s\n", result.Message)

		if *debug {
			fmt.Println(result)
		}
	} else if flag.Arg(0) == "ipaddress" {
		result, err := vt.IpAddressReport(flag.Args()[1])

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s\n", result.Message)

		if *debug {
			fmt.Println(result)
		}
	} else if flag.Arg(0) == "comment" {
		result, err := vt.Comment(*resource, flag.Args()[1])

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s\n", result.Message)

		if *debug {
			fmt.Println(result)
		}
	} else if flag.Arg(0) == "report" {
		result, err := vt.Report(flag.Args()[1])

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s\n", result.Message)

		if *debug {
			fmt.Println(result)
		}
	} else if flag.Arg(0) == "report-url" {
		u, err := url.Parse(flag.Args()[1])
		if err != nil {
			log.Fatal(err)
		}

		result, err := vt.ReportUrl(u)

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s\n", result.Message)

		if *debug {
			fmt.Println(result)
		}
	} else if flag.Arg(0) == "domain" {
		result, err := vt.DomainReport(flag.Args()[1])

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s\n", result.Message)

		if *debug {
			fmt.Println(result)
		}
	} else {
		fmt.Println("Usage:")
		fmt.Println("")
		fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) scan {file} {file} ...")
		fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) rescan {hash} {hash} ...")
		fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) report 99017f6eebbac24f351415dd410d522d")
		fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) scan-url {url} {url} ...")
		fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) report-url www.google.com")
		fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) ipaddress 90.156.201.27")
		fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) domain 027.ru")
		fmt.Println("go run ./bin/vt.go --apikey {key} (--debug) --resource 99017f6eebbac24f351415dd410d522d comment \"How to disinfect you from this file... #disinfect #zbot\"")
	}

}
