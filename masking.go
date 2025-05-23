package main

import (
	"regexp"
	"strings"
)

func MaskPAN(pan string) (string, bool) {
	matched, _ := regexp.MatchString(`^[A-Z]{5}[0-9]{4}[A-Z]$`, pan)
	if matched {
		return pan[:2] + "XXX" + pan[5:], true
	}
	return "", false
}

func MaskAadhaar(aadhaar string) (string, bool) {
	digits := strings.ReplaceAll(strings.ReplaceAll(aadhaar, "-", ""), " ", "")
	matched, _ := regexp.MatchString(`^[0-9]{12}$`, digits)
	if matched {
		return "XXXX-XXXX-" + digits[8:], true
	}
	return "", false
}

func MaskPhone(phone string) (string, bool) {
	digits := strings.ReplaceAll(phone, " ", "")
	matched, _ := regexp.MatchString(`^[6-9][0-9]{9}$`, digits)
	if matched {
		return digits[:2] + "*****" + digits[7:], true
	}
	return "", false
}

func MaskEmail(email string) (string, bool) {
	parts := strings.Split(email, "@")
	if len(parts) != 2 || len(parts[0]) < 2 {
		return "", false
	}
	return string(parts[0][0]) + "***@" + parts[1], true
}

func MaskGSTIN(gstin string) (string, bool) {
	matched, _ := regexp.MatchString(`^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}$`, gstin)
	if matched {
		return gstin[:5] + "*****" + gstin[10:], true
	}
	return "", false
}

func ApplyMask(t, v string) (string, bool) {
	switch strings.ToLower(t) {
	case "pan":
		return MaskPAN(v)
	case "aadhaar":
		return MaskAadhaar(v)
	case "phone":
		return MaskPhone(v)
	case "email":
		return MaskEmail(v)
	case "gstin":
		return MaskGSTIN(v)
	default:
		return "", false
	}
}

func DetectType(value string) string {
	if _, ok := MaskPAN(value); ok {
		return "pan"
	}
	if _, ok := MaskAadhaar(value); ok {
		return "aadhaar"
	}
	if _, ok := MaskPhone(value); ok {
		return "phone"
	}
	if _, ok := MaskEmail(value); ok {
		return "email"
	}
	if _, ok := MaskGSTIN(value); ok {
		return "gstin"
	}
	return ""
}
