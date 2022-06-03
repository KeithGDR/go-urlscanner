package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"drixevel.dev/go-urlscanner/internal/config"
)

type Config struct {
	APIKey string `json:"apikey"`
}

type response struct {
	Url       string `json:"url"`
	Malicious bool   `json:"malicious"`
}

type Positive struct {
	Positives int `json:"positives"`
}

func main() {
	println("Launching our web server...")

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleBase)
	mux.HandleFunc("/scan", handleScan)
	err := http.ListenAndServe(":8090", mux)

	if err == nil {
		panic(err)
	}
}

func handleBase(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Usage: /scan?url=<url>")
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	println("Scan request received...")
	defer println("Scan request processed.")

	url := r.URL.Query().Get("url")

	if url == "" {
		w.Header().Set("x-missing-field", "url")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	scan_results := VirusTotalScan(url)

	data := &response{Url: url, Malicious: scan_results}
	results, _ := json.Marshal(data)

	io.WriteString(w, fmt.Sprintf("%s", string(results)))
}

func VirusTotalScan(url string) bool {
	req, err := http.NewRequest("GET", "https://www.virustotal.com/vtapi/v2/url/report", nil)

	if req == nil {
		log.Fatal(err)
	}

	req.Header.Add("Accept", "application/json")

	var cfg Config

	if err := config.ParseConfig(&cfg); err != nil {
		log.Fatal(err)
	}

	q := req.URL.Query()
	q.Add("apikey", cfg.APIKey)
	q.Add("resource", url)
	q.Add("allinfo", "false")
	q.Add("scan", "0")
	req.URL.RawQuery = q.Encode()

	res, err := http.DefaultClient.Do(req)

	if res == nil {
		log.Fatal(err)
	}

	defer res.Body.Close()
	body, _ := ioutil.ReadAll(res.Body)

	var iot Positive
	err = json.Unmarshal(body, &iot)

	if err != nil {
		log.Fatal(err)
	}

	return iot.Positives > 0
}
