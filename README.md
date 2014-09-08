go-virustotal
=============

VirusTotal public api interface implementation in Golang.


Usage
=====

```
go run ./bin/vt.go --apikey {key} --debug scan {path ...}
go run ./bin/vt.go --apikey {key} --debug rescan {hash ...}
go run ./bin/vt.go --apikey {key} --debug ipaddress 90.156.201.27
```

