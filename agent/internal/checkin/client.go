package checkin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/SleuthCo/clawshield/shared/models"
)

// Client communicates with the ClawShield Management Hub.
type Client struct {
	HubURL     string
	HTTPClient *http.Client
}

// NewClient creates a new Hub client.
func NewClient(hubURL string) *Client {
	return &Client{
		HubURL: hubURL,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Enroll sends an enrollment request to the Hub and returns the enrollment response.
func (c *Client) Enroll(token, hostname string, tags []string) (*models.EnrollmentResponse, error) {
	req := &models.EnrollmentRequest{
		Token:    token,
		Hostname: hostname,
		Tags:     tags,
	}
	result := &models.EnrollmentResponse{}
	err := c.doPost("/api/v1/enroll", req, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Checkin sends a check-in request to the Hub and returns the check-in response.
func (c *Client) Checkin(req *models.CheckinRequest) (*models.CheckinResponse, error) {
	result := &models.CheckinResponse{}
	err := c.doPost("/api/v1/checkin", req, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// doPost is a helper that marshals body to JSON, POSTs to hubURL+path,
// checks the status code, and unmarshals the response into result.
func (c *Client) doPost(path string, body interface{}, result interface{}) error {
	// Marshal request body
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create POST request
	url := c.HubURL + path
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		limitedBody := io.LimitReader(resp.Body, 1024) // 1KB for error messages
		respBody, _ := io.ReadAll(limitedBody)
		return fmt.Errorf("hub returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Unmarshal response with size limit to prevent memory exhaustion
	limitedBody := io.LimitReader(resp.Body, 10*1024*1024) // 10MB limit
	if err := json.NewDecoder(limitedBody).Decode(result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	return nil
}
