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

package virustotal

import (
        "net/url"
        "fmt"
	"bytes"
	"encoding/json"
	"io"
        "strings"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"path/filepath"
)

type VirusTotal struct {
	apikey string
}

type VirusTotalResponse struct {
	ResponseCode int    `json:"response_code"`
	Message      string `json:"verbose_msg"`
}

type ScanResponse struct {
        VirusTotalResponse

	ScanId       string `json:"scan_id"`
	Sha1         string `json:"sha1"`
	Resource     string `json:"resource"`
	Sha256       string `json:"sha256"`
	Permalink    string `json:"permalink"`
	Md5          string `json:"md5"`
}

func (sr *ScanResponse) String() string {
    return fmt.Sprintf("scanid: %s, resource: %s, permalink: %s, md5: %s", sr.ScanId, sr.Resource, sr.Permalink, sr.Md5)
}

type RescanResponse struct {
    ScanResponse
}

func (sr *RescanResponse) String() string {
    return fmt.Sprintf("scanid: %s, resource: %s, permalink: %s, md5: %s", sr.ScanId, sr.Resource, sr.Permalink, sr.Md5)
}

type DetectedUrl struct {
    ScanDate string `json:"scan_date"`
    Url string `json:"url"`
    Positives int `json:"positives"`
    Total int `json:"total"`
}

type Resolution struct {
    LastResolved string `json:"last_resolved"`
    Hostname string `json:"hostname"`
}

type IpAddressReportResponse struct {
    VirusTotalResponse
    Resolutions []Resolution  `json:"resolutions"`
    DetectedUrls []DetectedUrl `json:"detected_urls"`
}

func NewVirusTotal(apikey string) (*VirusTotal, error) {
	vt := &VirusTotal{apikey: apikey}
	return vt, nil
}

func (vt *VirusTotal) IpAddressReport(ip string) (*IpAddressReportResponse, error) {
    u, err := url.Parse("http://www.virustotal.com/vtapi/v2/ip-address/report")
    u.RawQuery = url.Values{"apikey": {vt.apikey}, "ip": {ip}}.Encode()

    resp, err := http.Get(u.String())

    if err != nil {
            return nil, err
    }

    defer resp.Body.Close()

    contents, err := ioutil.ReadAll(resp.Body)
    if err != nil {
            return nil, err
    }

    var ipAddressResponse = &IpAddressReportResponse{}

    err = json.Unmarshal(contents, &ipAddressResponse)

    return ipAddressResponse, err
}


func (vt *VirusTotal) Rescan(hash []string) (*RescanResponse, error) {
    resource := strings.Join(hash, ",")

    resp, err := http.PostForm("https://www.virustotal.com/vtapi/v2/file/rescan", url.Values{"apikey": {vt.apikey}, "resource": {resource}})

    if err != nil {
            return nil, err
    }

    defer resp.Body.Close()

    contents, err := ioutil.ReadAll(resp.Body)
    if err != nil {
            return nil, err
    }

    var rescanResponse = &RescanResponse{}

    err = json.Unmarshal(contents, &rescanResponse)

    return rescanResponse, err
}

func (vt *VirusTotal) Scan(path string, file io.Reader) (*ScanResponse, error) {
	params := map[string]string{
		"apikey": vt.apikey,
	}

	request, err := newfileUploadRequest("http://www.virustotal.com/vtapi/v2/file/scan", params, path, file)

	if err != nil {
		return nil, err
	}

	client := &http.Client{}

	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var scanResponse = &ScanResponse{}
	err = json.Unmarshal(contents, &scanResponse)

	return scanResponse, err
}

// Creates a new file upload http request with optional extra params
func newfileUploadRequest(uri string, params map[string]string, path string, file io.Reader) (*http.Request, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	for key, val := range params {
		_ = writer.WriteField(key, val)
	}

	part, err := writer.CreateFormFile("file", filepath.Base(path))
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(part, file)

	err = writer.Close()

	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", uri, body)

	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, err
}
