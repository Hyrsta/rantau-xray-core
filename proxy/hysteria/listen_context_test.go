package hysteria

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet/hysteria"
)

// Rantau: app/proxyman/inbound gives a Hysteria inbound's listener its users through ListenContext (an
// interface there, so the inbound package does not link Hysteria), as it did through the Server type.
func TestListenContextCarriesTheValidator(t *testing.T) {
	validator := account.NewValidator()
	var inbound interface {
		ListenContext(context.Context) context.Context
	} = &Server{validator: validator}
	if got := hysteria.ValidatorFromContext(inbound.ListenContext(context.Background())); got != validator {
		t.Fatalf("validator in the listener's context = %p, want %p", got, validator)
	}
}
