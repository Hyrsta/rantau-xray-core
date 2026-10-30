package session

import (
	"context"
	"testing"
)

func TestPreconnectDisabledIsIndependentAndPreservesContext(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	ctx := ContextWithPreconnectDisabled(parent)
	if !IsPreconnectDisabled(ctx) || IsPreconnect(ctx) || IsPreconnectDisabled(parent) || IsPreconnectDisabled(ContextWithPreconnect(parent)) {
		t.Fatal("health and speculative authentication markers overlap")
	}
	child := ContextWithOutbounds(ctx, []*Outbound{{Name: "vless"}})
	if !IsPreconnectDisabled(child) || IsPreconnect(child) {
		t.Fatal("session wrapping lost health marker")
	}
	cancel()
	select {
	case <-child.Done():
	default:
		t.Fatal("health marker detached request cancellation")
	}
}
