package main

import "testing"

func TestMaskPAN(t *testing.T) {
	masked, ok := MaskPAN("ABCDE1234F")
	if !ok {
		t.Fatal("expected valid PAN")
	}
	if masked != "ABXXX1234F" {
		t.Fatalf("got %q", masked)
	}
}

func TestMaskAadhaar(t *testing.T) {
	masked, ok := MaskAadhaar("1234-5678-9012")
	if !ok {
		t.Fatal("expected valid aadhaar")
	}
	if masked != "XXXX-XXXX-9012" {
		t.Fatalf("got %q", masked)
	}
}

func TestMaskPhone(t *testing.T) {
	masked, ok := MaskPhone("9876543210")
	if !ok {
		t.Fatal("expected valid phone")
	}
	if masked != "98*****210" {
		t.Fatalf("got %q", masked)
	}
}

func TestMaskEmail(t *testing.T) {
	masked, ok := MaskEmail("ankit@example.com")
	if !ok {
		t.Fatal("expected valid email")
	}
	if masked != "a***@example.com" {
		t.Fatalf("got %q", masked)
	}
}

func TestMaskGSTIN(t *testing.T) {
	masked, ok := MaskGSTIN("22AAAAA0000A1Z5")
	if !ok {
		t.Fatal("expected valid GSTIN")
	}
	if masked != "22AAA*****0A1Z5" {
		t.Fatalf("got %q", masked)
	}
}

func TestDetectType(t *testing.T) {
	cases := map[string]string{
		"ABCDE1234F":       "pan",
		"9876543210":       "phone",
		"ankit@example.com": "email",
	}
	for value, want := range cases {
		if got := DetectType(value); got != want {
			t.Fatalf("DetectType(%q) = %q, want %q", value, got, want)
		}
	}
}
