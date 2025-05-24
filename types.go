package main

type MaskRequest struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type MaskResponse struct {
	Masked string `json:"masked"`
}

type BulkRequest []MaskRequest
type BulkResponse []MaskResponse

type ValidationResponse struct {
	Valid bool `json:"valid"`
}

type DetectionRequest struct {
	Value string `json:"value"`
}

type DetectionResponse struct {
	Type string `json:"type,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}
