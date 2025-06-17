package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func SendCSR(url string, csr string) error {
	type KeyMeta struct {
		Identifier string `json:"identifier"`
	}

	type RequestBody struct {
		CSR      string  `json:"csr"`
		KeyMeta  KeyMeta `json:"key_meta"`
		Validity int     `json:"validity"`
	}

	body := RequestBody{
		CSR: csr,
		KeyMeta: KeyMeta{
			Identifier: "athenz",
		},
		Validity: 30 * 24 * 60 * 60, // 30 days in seconds
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode > http.StatusBadRequest {
		return fmt.Errorf("received non-OK response: %s", resp.Status)
	}

	var responseBody map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&responseBody); err != nil {
		return fmt.Errorf("failed to parse JSON response: %v", err)
	}

	fmt.Printf("%+v\n", responseBody["cert"])

	return nil
}
