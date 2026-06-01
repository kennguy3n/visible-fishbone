package postgres

import (
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Each repository constructor returns the typed implementation
// bound to the shared Store. They live in this file so the
// type-assertion lines below sit next to one another — a single
// place to read when verifying interface compliance.

// NewTenantRepository binds the Store to repository.TenantRepository.
func (s *Store) NewTenantRepository() *TenantRepository { return &TenantRepository{s: s} }

// NewSiteRepository binds the Store to repository.SiteRepository.
func (s *Store) NewSiteRepository() *SiteRepository { return &SiteRepository{s: s} }

// NewUserRepository binds the Store to repository.UserRepository.
func (s *Store) NewUserRepository() *UserRepository { return &UserRepository{s: s} }

// NewDeviceRepository binds the Store to repository.DeviceRepository.
func (s *Store) NewDeviceRepository() *DeviceRepository { return &DeviceRepository{s: s} }

// NewRoleRepository binds the Store to repository.RoleRepository.
func (s *Store) NewRoleRepository() *RoleRepository { return &RoleRepository{s: s} }

// NewClaimTokenRepository binds the Store to repository.ClaimTokenRepository.
func (s *Store) NewClaimTokenRepository() *ClaimTokenRepository { return &ClaimTokenRepository{s: s} }

// NewAuditLogRepository binds the Store to repository.AuditLogRepository.
func (s *Store) NewAuditLogRepository() *AuditLogRepository { return &AuditLogRepository{s: s} }

// NewPolicyRepository binds the Store to repository.PolicyRepository.
func (s *Store) NewPolicyRepository() *PolicyRepository { return &PolicyRepository{s: s} }

// NewPolicySigningKeyRepository binds the Store to repository.PolicySigningKeyRepository.
func (s *Store) NewPolicySigningKeyRepository() *PolicySigningKeyRepository {
	return &PolicySigningKeyRepository{s: s}
}

// NewPolicyRolloutRepository binds the Store to repository.PolicyRolloutRepository.
func (s *Store) NewPolicyRolloutRepository() *PolicyRolloutRepository {
	return &PolicyRolloutRepository{s: s}
}

// NewTenantAPIKeyRepository binds the Store to repository.TenantAPIKeyRepository.
func (s *Store) NewTenantAPIKeyRepository() *TenantAPIKeyRepository {
	return &TenantAPIKeyRepository{s: s}
}

// NewWebhookEndpointRepository binds the Store to repository.WebhookEndpointRepository.
func (s *Store) NewWebhookEndpointRepository() *WebhookEndpointRepository {
	return &WebhookEndpointRepository{s: s}
}

// NewWebhookDeliveryRepository binds the Store to repository.WebhookDeliveryRepository.
func (s *Store) NewWebhookDeliveryRepository() *WebhookDeliveryRepository {
	return &WebhookDeliveryRepository{s: s}
}

// NewAppRegistryRepository binds the Store to repository.AppRegistryRepository.
func (s *Store) NewAppRegistryRepository() *AppRegistryRepository {
	return &AppRegistryRepository{s: s}
}

// NewAppRegistryOverrideRepository binds the Store to repository.AppRegistryOverrideRepository.
func (s *Store) NewAppRegistryOverrideRepository() *AppRegistryOverrideRepository {
	return &AppRegistryOverrideRepository{s: s}
}

// Compile-time interface compliance asserts. Keeping these in this
// file means a single grep tells us "did the postgres package
// implement every interface?" without scanning eight files.
var (
	_ repository.TenantRepository              = (*TenantRepository)(nil)
	_ repository.SiteRepository                = (*SiteRepository)(nil)
	_ repository.UserRepository                = (*UserRepository)(nil)
	_ repository.DeviceRepository              = (*DeviceRepository)(nil)
	_ repository.RoleRepository                = (*RoleRepository)(nil)
	_ repository.ClaimTokenRepository          = (*ClaimTokenRepository)(nil)
	_ repository.AuditLogRepository            = (*AuditLogRepository)(nil)
	_ repository.PolicyRepository              = (*PolicyRepository)(nil)
	_ repository.PolicySigningKeyRepository    = (*PolicySigningKeyRepository)(nil)
	_ repository.PolicyRolloutRepository       = (*PolicyRolloutRepository)(nil)
	_ repository.TenantAPIKeyRepository        = (*TenantAPIKeyRepository)(nil)
	_ repository.WebhookEndpointRepository     = (*WebhookEndpointRepository)(nil)
	_ repository.WebhookDeliveryRepository     = (*WebhookDeliveryRepository)(nil)
	_ repository.AppRegistryRepository         = (*AppRegistryRepository)(nil)
	_ repository.AppRegistryOverrideRepository = (*AppRegistryOverrideRepository)(nil)
)
