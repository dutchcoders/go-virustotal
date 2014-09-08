go-virustotal
=============

VirusTotal public api interface implementation in Golang.


Usage
=====

You can also set the environment variable VIRUSTOTAL_APIKEY to the api key.

```
go run ./bin/vt.go --apikey {key} --debug scan {path ...}
go run ./bin/vt.go --apikey {key} --debug rescan {hash ...}
go run ./bin/vt.go --apikey {key} --debug ipaddress 90.156.201.27
go run ./bin/vt.go --apikey {key} --debug domain 027.ru
```


