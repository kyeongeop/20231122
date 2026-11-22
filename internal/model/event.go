package model

import (
	"errors"
	"fmt"
)

// Event kinds used by the verification-code replay pipeline.
const (
	KindIssue   = "issue"   // a verification code is issued to a user
	KindConsume = "consume" // a verification code is presented and consumed
)

// Event is one raw record reported by a device.
//
// ObservedAt is the device-local wall clock in Unix milliseconds. Devices are
// allowed to drift, so ordering uses Sequence, not ObservedAt. OffsetMs is the
// device's known offset relative to the reference clock (reference = local +
// offset); it is supplied by out-of-band clock discipline and may be zero.
type Event struct {
	Sequence   int64  `json:"sequence"`
	DeviceID   string `json:"device_id"`
	Code       string `json:"code"`
	UserID     string `json:"user_id"`
	Kind       string `json:"kind"`
	ObservedAt int64  `json:"observed_at"`
	OffsetMs   int64  `json:"offset_ms"`
}

// ReferenceAt returns the clock-disciplined timestamp of the event.
func (e Event) ReferenceAt() int64 {
	return e.ObservedAt + e.OffsetMs
}

// Validate performs schema-level validation only; cross-record analysis lives
// in the detect package so it remains pure and fuzzable.
func (e Event) Validate() error {
	if e.Sequence < 0 {
		return errors.New("sequence must be non-negative")
	}
	if e.DeviceID == "" {
		return errors.New("device_id is required")
	}
	if e.Code == "" {
		return errors.New("code is required")
	}
	if e.UserID == "" {
		return errors.New("user_id is required")
	}
	switch e.Kind {
	case KindIssue, KindConsume:
	default:
		return fmt.Errorf("unknown kind %q", e.Kind)
	}
	if e.ObservedAt < 0 {
		return errors.New("observed_at must be non-negative")
	}
	return nil
}
