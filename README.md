go-virustotal
=============

VirusTotal public api interface implementation in Golang.


Usage
=====

You can also set the environment variable VIRUSTOTAL_APIKEY to the api key.

```
go run ./bin/vt.go --apikey {key} (--debug) scan {file} {file} ...
go run ./bin/vt.go --apikey {key} (--debug) rescan {hash} {hash} ...
go run ./bin/vt.go --apikey {key} (--debug) report 99017f6eebbac24f351415dd410d522d
go run ./bin/vt.go --apikey {key} (--debug) scan-url {url} {url} ...
go run ./bin/vt.go --apikey {key} (--debug) report-url www.google.com
go run ./bin/vt.go --apikey {key} (--debug) ipaddress 90.156.201.27
go run ./bin/vt.go --apikey {key} (--debug) domain 027.ru
go run ./bin/vt.go --apikey {key} (--debug) --resource 99017f6eebbac24f351415dd410d522d comment "How to disinfect you from this file... #disinfect #zbot"
```


