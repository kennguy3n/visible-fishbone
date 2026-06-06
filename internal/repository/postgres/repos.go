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

// NewBaselineModelRepository binds the Store to repository.BaselineModelRepository.
func (s *Store) NewBaselineModelRepository() *BaselineModelRepository {
	return &BaselineModelRepository{s: s}
}

// NewAlertRepository binds the Store to repository.AlertRepository.
func (s *Store) NewAlertRepository() *AlertRepository { return &AlertRepository{s: s} }

// NewAlertSuppressionRepository binds the Store to repository.AlertSuppressionRepository.
func (s *Store) NewAlertSuppressionRepository() *AlertSuppressionRepository {
	return &AlertSuppressionRepository{s: s}
}

// NewAlertFeedbackRepository binds the Store to repository.AlertFeedbackRepository.
func (s *Store) NewAlertFeedbackRepository() *AlertFeedbackRepository {
	return &AlertFeedbackRepository{s: s}
}

// NewIntegrationConnectorRepository binds the Store to repository.IntegrationConnectorRepository.
func (s *Store) NewIntegrationConnectorRepository() *IntegrationConnectorRepository {
	return &IntegrationConnectorRepository{s: s}
}

// NewIntegrationDeliveryRepository binds the Store to repository.IntegrationDeliveryRepository.
func (s *Store) NewIntegrationDeliveryRepository() *IntegrationDeliveryRepository {
	return &IntegrationDeliveryRepository{s: s}
}

// NewMSPRepository binds the Store to repository.MSPRepository.
func (s *Store) NewMSPRepository() *MSPRepository { return &MSPRepository{s: s} }

// NewDeviceEnrollmentRepository binds the Store to repository.DeviceEnrollmentRepository.
func (s *Store) NewDeviceEnrollmentRepository() *DeviceEnrollmentRepository {
	return &DeviceEnrollmentRepository{s: s}
}

// NewDeviceIdentityBindingRepository binds the Store to repository.DeviceIdentityBindingRepository.
func (s *Store) NewDeviceIdentityBindingRepository() *DeviceIdentityBindingRepository {
	return &DeviceIdentityBindingRepository{s: s}
}

// NewResidencyAuditRepository binds the Store to repository.ResidencyAuditRepository.
func (s *Store) NewResidencyAuditRepository() *ResidencyAuditRepository {
	return &ResidencyAuditRepository{s: s}
}

// NewCASBConnectorRepository binds the Store to repository.CASBConnectorRepository.
func (s *Store) NewCASBConnectorRepository() *CASBConnectorRepository {
	return &CASBConnectorRepository{s: s}
}

// NewCASBDiscoveredAppRepository binds the Store to repository.CASBDiscoveredAppRepository.
func (s *Store) NewCASBDiscoveredAppRepository() *CASBDiscoveredAppRepository {
	return &CASBDiscoveredAppRepository{s: s}
}

// NewCASBPostureCheckRepository binds the Store to repository.CASBPostureCheckRepository.
func (s *Store) NewCASBPostureCheckRepository() *CASBPostureCheckRepository {
	return &CASBPostureCheckRepository{s: s}
}

// NewInlineCASBRuleRepository binds the Store to repository.InlineCASBRuleRepository.
func (s *Store) NewInlineCASBRuleRepository() *InlineCASBRuleRepository {
	return &InlineCASBRuleRepository{s: s}
}

// NewSandboxVerdictRepository binds the Store to repository.SandboxVerdictRepository.
func (s *Store) NewSandboxVerdictRepository() *SandboxVerdictRepository {
	return &SandboxVerdictRepository{s: s}
}

// NewRBISessionRepository binds the Store to repository.RBISessionRepository.
func (s *Store) NewRBISessionRepository() *RBISessionRepository {
	return &RBISessionRepository{s: s}
}

// NewAICorrelationRepository binds the Store to repository.AICorrelationRepository.
func (s *Store) NewAICorrelationRepository() *AICorrelationRepository {
	return &AICorrelationRepository{s: s}
}

// NewComplianceReportRepository binds the Store to repository.ComplianceReportRepository.
func (s *Store) NewComplianceReportRepository() *ComplianceReportRepository {
	return &ComplianceReportRepository{s: s}
}

// NewComplianceEvidenceRepository binds the Store to repository.ComplianceEvidenceRepository.
func (s *Store) NewComplianceEvidenceRepository() *ComplianceEvidenceRepository {
	return &ComplianceEvidenceRepository{s: s}
}

// NewPlaybookRepository binds the Store to repository.PlaybookRepository.
func (s *Store) NewPlaybookRepository() *PlaybookRepository {
	return &PlaybookRepository{s: s}
}

// NewPlaybookExecutionRepository binds the Store to repository.PlaybookExecutionRepository.
func (s *Store) NewPlaybookExecutionRepository() *PlaybookExecutionRepository {
	return &PlaybookExecutionRepository{s: s}
}

// NewPlaybookApprovalRepository binds the Store to repository.PlaybookApprovalRepository.
func (s *Store) NewPlaybookApprovalRepository() *PlaybookApprovalRepository {
	return &PlaybookApprovalRepository{s: s}
}

// NewPolicyReviewScheduleRepository binds the Store to repository.PolicyReviewScheduleRepository.
func (s *Store) NewPolicyReviewScheduleRepository() *PolicyReviewScheduleRepository {
	return &PolicyReviewScheduleRepository{s: s}
}

// NewOpsHealthSnapshotRepository binds the Store to repository.OpsHealthSnapshotRepository.
func (s *Store) NewOpsHealthSnapshotRepository() *OpsHealthSnapshotRepository {
	return &OpsHealthSnapshotRepository{s: s}
}

// NewAISuggestionRepository binds the Store to repository.AISuggestionRepository.
func (s *Store) NewAISuggestionRepository() *AISuggestionRepository {
	return &AISuggestionRepository{s: s}
}

// NewKBEntryRepository binds the Store to repository.KBEntryRepository.
func (s *Store) NewKBEntryRepository() *KBEntryRepository {
	return &KBEntryRepository{s: s}
}

// NewTroubleshootSessionRepository binds the Store to repository.TroubleshootSessionRepository.
func (s *Store) NewTroubleshootSessionRepository() *TroubleshootSessionRepository {
	return &TroubleshootSessionRepository{s: s}
}

// NewIDPConfigRepository binds the Store to repository.IDPConfigRepository.
func (s *Store) NewIDPConfigRepository() *IDPConfigRepository {
	return &IDPConfigRepository{s: s}
}

// Compile-time interface compliance asserts. Keeping these in this
// file means a single grep tells us "did the postgres package
// implement every interface?" without scanning eight files.
var (
	_ repository.TenantRepository                = (*TenantRepository)(nil)
	_ repository.SiteRepository                  = (*SiteRepository)(nil)
	_ repository.UserRepository                  = (*UserRepository)(nil)
	_ repository.DeviceRepository                = (*DeviceRepository)(nil)
	_ repository.RoleRepository                  = (*RoleRepository)(nil)
	_ repository.ClaimTokenRepository            = (*ClaimTokenRepository)(nil)
	_ repository.AuditLogRepository              = (*AuditLogRepository)(nil)
	_ repository.PolicyRepository                = (*PolicyRepository)(nil)
	_ repository.PolicySigningKeyRepository      = (*PolicySigningKeyRepository)(nil)
	_ repository.PolicyRolloutRepository         = (*PolicyRolloutRepository)(nil)
	_ repository.TenantAPIKeyRepository          = (*TenantAPIKeyRepository)(nil)
	_ repository.WebhookEndpointRepository       = (*WebhookEndpointRepository)(nil)
	_ repository.WebhookDeliveryRepository       = (*WebhookDeliveryRepository)(nil)
	_ repository.AppRegistryRepository           = (*AppRegistryRepository)(nil)
	_ repository.AppRegistryOverrideRepository   = (*AppRegistryOverrideRepository)(nil)
	_ repository.BaselineModelRepository         = (*BaselineModelRepository)(nil)
	_ repository.AlertRepository                 = (*AlertRepository)(nil)
	_ repository.AlertSuppressionRepository      = (*AlertSuppressionRepository)(nil)
	_ repository.AlertFeedbackRepository         = (*AlertFeedbackRepository)(nil)
	_ repository.IntegrationConnectorRepository  = (*IntegrationConnectorRepository)(nil)
	_ repository.IntegrationDeliveryRepository   = (*IntegrationDeliveryRepository)(nil)
	_ repository.MSPRepository                   = (*MSPRepository)(nil)
	_ repository.DeviceEnrollmentRepository      = (*DeviceEnrollmentRepository)(nil)
	_ repository.DeviceIdentityBindingRepository = (*DeviceIdentityBindingRepository)(nil)
	_ repository.CASBConnectorRepository         = (*CASBConnectorRepository)(nil)
	_ repository.CASBDiscoveredAppRepository     = (*CASBDiscoveredAppRepository)(nil)
	_ repository.CASBPostureCheckRepository      = (*CASBPostureCheckRepository)(nil)
	_ repository.AICorrelationRepository         = (*AICorrelationRepository)(nil)
	_ repository.ComplianceReportRepository      = (*ComplianceReportRepository)(nil)
	_ repository.ComplianceEvidenceRepository    = (*ComplianceEvidenceRepository)(nil)
	_ repository.PlaybookRepository              = (*PlaybookRepository)(nil)
	_ repository.PlaybookExecutionRepository     = (*PlaybookExecutionRepository)(nil)
	_ repository.PlaybookApprovalRepository      = (*PlaybookApprovalRepository)(nil)
	_ repository.PolicyReviewScheduleRepository  = (*PolicyReviewScheduleRepository)(nil)
	_ repository.OpsHealthSnapshotRepository     = (*OpsHealthSnapshotRepository)(nil)
	_ repository.AISuggestionRepository          = (*AISuggestionRepository)(nil)
	_ repository.KBEntryRepository               = (*KBEntryRepository)(nil)
	_ repository.TroubleshootSessionRepository   = (*TroubleshootSessionRepository)(nil)
	_ repository.IDPConfigRepository             = (*IDPConfigRepository)(nil)
	_ repository.ResidencyAuditRepository        = (*ResidencyAuditRepository)(nil)
)
