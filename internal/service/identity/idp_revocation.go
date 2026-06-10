package identity

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// MessagePublisher is the minimal NATS publish surface the revocation
// publisher needs. It matches the Publisher interface used by the
// playbook engine / executors so the same broker can back both.
type MessagePublisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// NATSRevocationPublisher pushes off-boarding revocations onto the ZTNA
// revocation subject the enforcement plane consumes
// (`sng.<tenant>.ztna.revoke`), reusing the wire shape emitted by the
// playbook revoke-access executor so a single downstream consumer
// handles both sources.
type NATSRevocationPublisher struct {
	pub MessagePublisher
}

// NewNATSRevocationPublisher wires a revocation publisher onto a message
// broker.
func NewNATSRevocationPublisher(pub MessagePublisher) *NATSRevocationPublisher {
	return &NATSRevocationPublisher{pub: pub}
}

// PublishRevocation emits a tenant-scoped revocation for an off-boarded
// user. The subject embeds the tenant id so the enforcement plane's
// per-tenant subscription only ever sees its own revocations.
func (p *NATSRevocationPublisher) PublishRevocation(ctx context.Context, tenantID, userID uuid.UUID, reason string) error {
	if p == nil || p.pub == nil {
		return nil
	}
	msg, err := json.Marshal(map[string]string{
		"action":    "revoke_access",
		"user_id":   userID.String(),
		"tenant_id": tenantID.String(),
		"reason":    reason,
		"source":    "idp_sync",
	})
	if err != nil {
		return fmt.Errorf("marshal revocation: %w", err)
	}
	subject := fmt.Sprintf("sng.%s.ztna.revoke", tenantID)
	if err := p.pub.Publish(ctx, subject, msg); err != nil {
		return fmt.Errorf("publish revocation: %w", err)
	}
	return nil
}
