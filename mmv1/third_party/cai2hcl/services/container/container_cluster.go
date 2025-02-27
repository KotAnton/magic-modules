package container

import (
	"encoding/json"
	"fmt"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/caiasset"
	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/cai2hcl/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/zclconf/go-cty/cty"
	"google.golang.org/api/container/v1"
)

// ContainerClusterAssetType is the CAI asset type name for GKE clusters
const ContainerClusterAssetType string = "container.googleapis.com/Cluster"

// ContainerClusterSchemaName is the TF resource schema name for GKE clusters
const ContainerClusterSchemaName string = "google_container_cluster"

// ContainerClusterConverter for GKE cluster resources
type ContainerClusterConverter struct {
	name   string
	schema map[string]*schema.Schema
}

// NewContainerClusterConverter returns an HCL converter for GKE clusters
func NewContainerClusterConverter(provider *schema.Provider) common.Converter {
	schema := provider.ResourcesMap[ContainerClusterSchemaName].Schema

	return &ContainerClusterConverter{
		name:   ContainerClusterSchemaName,
		schema: schema,
	}
}

// Convert converts asset to HCL resource blocks
func (c *ContainerClusterConverter) Convert(assets []*caiasset.Asset) ([]*common.HCLResourceBlock, error) {
	var blocks []*common.HCLResourceBlock
	for _, asset := range assets {
		if asset == nil {
			continue
		}
		if asset.Resource != nil && asset.Resource.Data != nil {
			block, err := c.convertResourceData(asset)
			if err != nil {
				return nil, err
			}
			blocks = append(blocks, block)
		}
	}
	return blocks, nil
}

func (c *ContainerClusterConverter) convertResourceData(asset *caiasset.Asset) (*common.HCLResourceBlock, error) {
	if asset == nil || asset.Resource == nil || asset.Resource.Data == nil {
		return nil, fmt.Errorf("asset resource data is nil")
	}

	var cluster *container.Cluster
	if err := common.DecodeJSON(asset.Resource.Data, &cluster); err != nil {
		return nil, err
	}

	hclData := make(map[string]interface{})
	
	// Determine if this is an Autopilot cluster - this affects many other fields
	isAutopilot := cluster.Autopilot != nil && cluster.Autopilot.Enabled
	
	// Basic cluster properties
	hclData["name"] = cluster.Name
	hclData["location"] = cluster.Location
	hclData["description"] = cluster.Description
	
	// For Autopilot clusters, don't set initial_node_count or node_config
	// as these are managed by Google and not compatible with Autopilot
	if !isAutopilot {
		hclData["initial_node_count"] = cluster.InitialNodeCount
		
		// Add node locations if present
		if len(cluster.Locations) > 0 {
			hclData["node_locations"] = cluster.Locations
		}
		
		// Convert Node Config if present
		if cluster.NodeConfig != nil {
			hclData["node_config"] = flattenNodeConfig(cluster.NodeConfig)
		}
	} else {
		// For Autopilot, explicitly set enable_autopilot to true
		hclData["enable_autopilot"] = true
	}
	
	// Network configuration
	hclData["network"] = common.ParseFieldValue(cluster.Network, "networks")
	hclData["subnetwork"] = common.ParseFieldValue(cluster.Subnetwork, "subnetworks")
	
	// Handle CIDR fields - prefer IP allocation policy over legacy cluster_ipv4_cidr
	// to avoid conflicting configurations
	if cluster.IpAllocationPolicy != nil && 
	   (cluster.IpAllocationPolicy.ClusterIpv4CidrBlock != "" || 
	    cluster.IpAllocationPolicy.ServicesIpv4CidrBlock != "" ||
		cluster.IpAllocationPolicy.ClusterSecondaryRangeName != "" ||
		cluster.IpAllocationPolicy.ServicesSecondaryRangeName != "") {
		hclData["ip_allocation_policy"] = flattenIPAllocationPolicy(cluster.IpAllocationPolicy)
	} else if cluster.ClusterIpv4Cidr != "" {
		// Only use legacy cidr if ip_allocation_policy isn't defined
		hclData["cluster_ipv4_cidr"] = cluster.ClusterIpv4Cidr
	}
	
	// Convert addons config
	if cluster.AddonsConfig != nil {
		hclData["addons_config"] = flattenAddonsConfig(cluster.AddonsConfig)
	}
	
	// Convert Master Auth
	if cluster.MasterAuth != nil {
		masterAuth := flattenMasterAuth(cluster.MasterAuth)
		if len(masterAuth) > 0 {
			hclData["master_auth"] = masterAuth
		}
	}
	
	// Convert Private Cluster Config
	if cluster.PrivateClusterConfig != nil {
		hclData["private_cluster_config"] = flattenPrivateClusterConfig(cluster.PrivateClusterConfig)
	}
	
	// Convert Network Policy
	if cluster.NetworkPolicy != nil {
		hclData["network_policy"] = flattenNetworkPolicy(cluster.NetworkPolicy)
	}
	
	// Convert Master Authorized Networks Config
	if cluster.MasterAuthorizedNetworksConfig != nil {
		hclData["master_authorized_networks_config"] = flattenMasterAuthorizedNetworksConfig(cluster.MasterAuthorizedNetworksConfig)
	}
	
	// Handle fields that are directly mapped
	// Don't set kubernetes alpha for Autopilot clusters
	if !isAutopilot && cluster.EnableKubernetesAlpha {
		hclData["enable_kubernetes_alpha"] = cluster.EnableKubernetesAlpha
	}
	
	if cluster.LegacyAbac != nil && cluster.LegacyAbac.Enabled {
		hclData["enable_legacy_abac"] = cluster.LegacyAbac.Enabled
	}
	
	// Services
	if cluster.LoggingService != "" {
		hclData["logging_service"] = cluster.LoggingService
	}
	
	if cluster.MonitoringService != "" {
		hclData["monitoring_service"] = cluster.MonitoringService
	}
	
	// Resource labels
	if cluster.ResourceLabels != nil && len(cluster.ResourceLabels) > 0 {
		hclData["resource_labels"] = cluster.ResourceLabels
	}
	
	// Default max pods per node - not applicable for Autopilot
	if !isAutopilot && cluster.DefaultMaxPodsConstraint != nil {
		hclData["default_max_pods_per_node"] = cluster.DefaultMaxPodsConstraint.MaxPodsPerNode
	}

	// Release channel
	if cluster.ReleaseChannel != nil {
		hclData["release_channel"] = flattenReleaseChannel(cluster.ReleaseChannel)
	}

	// Database encryption
	if cluster.DatabaseEncryption != nil {
		dbEncryption := flattenDatabaseEncryption(cluster.DatabaseEncryption)
		if len(dbEncryption) > 0 {
			hclData["database_encryption"] = dbEncryption
		}
	}

	// Cluster Autoscaling - not applicable for Autopilot
	if !isAutopilot && cluster.Autoscaling != nil && cluster.Autoscaling.EnableNodeAutoprovisioning {
		hclData["cluster_autoscaling"] = flattenClusterAutoscaling(cluster.Autoscaling)
	}

	// Binary Authorization
	if cluster.BinaryAuthorization != nil {
		binAuth := flattenBinaryAuthorization(cluster.BinaryAuthorization)
		if len(binAuth) > 0 {
			hclData["binary_authorization"] = binAuth
		}
	}

	// Vertical Pod Autoscaling
	if cluster.VerticalPodAutoscaling != nil && cluster.VerticalPodAutoscaling.Enabled {
		hclData["vertical_pod_autoscaling"] = []map[string]interface{}{{
			"enabled": true,
		}}
	}

	// Workload Identity Config
	if cluster.WorkloadIdentityConfig != nil && cluster.WorkloadIdentityConfig.WorkloadPool != "" {
		hclData["workload_identity_config"] = []map[string]interface{}{{
			"workload_pool": cluster.WorkloadIdentityConfig.WorkloadPool,
		}}
	}

	// Confidential Nodes
	if cluster.ConfidentialNodes != nil && cluster.ConfidentialNodes.Enabled {
		hclData["confidential_nodes"] = []map[string]interface{}{{
			"enabled": true,
		}}
	}

	// Notification Config
	if cluster.NotificationConfig != nil && 
	   cluster.NotificationConfig.Pubsub != nil && 
	   (cluster.NotificationConfig.Pubsub.Enabled || cluster.NotificationConfig.Pubsub.Topic != "") {
		notificationConfig := make(map[string]interface{})
		notificationConfig["pubsub"] = []map[string]interface{}{{
			"enabled": cluster.NotificationConfig.Pubsub.Enabled,
			"topic":   cluster.NotificationConfig.Pubsub.Topic,
		}}
		
		hclData["notification_config"] = []map[string]interface{}{notificationConfig}
	}

	// Authenticator Groups Config
	if cluster.AuthenticatorGroupsConfig != nil && cluster.AuthenticatorGroupsConfig.SecurityGroup != "" {
		hclData["authenticator_groups_config"] = []map[string]interface{}{{
			"security_group": cluster.AuthenticatorGroupsConfig.SecurityGroup,
		}}
	}

	// Service External IPs Config
	if cluster.NetworkConfig != nil && 
	   cluster.NetworkConfig.ServiceExternalIpsConfig != nil {
		hclData["service_external_ips_config"] = []map[string]interface{}{{
			"enabled": cluster.NetworkConfig.ServiceExternalIpsConfig.Enabled,
		}}
	}

	// DNS Config
	if cluster.NetworkConfig != nil && 
	   cluster.NetworkConfig.DnsConfig != nil && 
	   cluster.NetworkConfig.DnsConfig.ClusterDns != "" {
		dnsConfig := map[string]interface{}{
			"cluster_dns": cluster.NetworkConfig.DnsConfig.ClusterDns,
		}
		
		if cluster.NetworkConfig.DnsConfig.ClusterDnsScope != "" {
			dnsConfig["cluster_dns_scope"] = cluster.NetworkConfig.DnsConfig.ClusterDnsScope
		}
		
		if cluster.NetworkConfig.DnsConfig.ClusterDnsDomain != "" {
			dnsConfig["cluster_dns_domain"] = cluster.NetworkConfig.DnsConfig.ClusterDnsDomain
		}
		
		hclData["dns_config"] = []map[string]interface{}{dnsConfig}
	}

	// Mesh Certificates
	if cluster.MeshCertificates != nil && cluster.MeshCertificates.EnableCertificates {
		hclData["mesh_certificates"] = []map[string]interface{}{{
			"enable_certificates": true,
		}}
	}

	// Cost Management Config
	if cluster.CostManagementConfig != nil && cluster.CostManagementConfig.Enabled {
		hclData["cost_management_config"] = []map[string]interface{}{{
			"enabled": true,
		}}
	}

	// Node Pool Auto Config - not applicable for Autopilot
	if !isAutopilot && 
	   cluster.NodePoolAutoConfig != nil && 
	   cluster.NodePoolAutoConfig.NetworkTags != nil &&
	   cluster.NodePoolAutoConfig.NetworkTags.Tags != nil && 
	   len(cluster.NodePoolAutoConfig.NetworkTags.Tags) > 0 {
		
		networkTags := map[string]interface{}{
			"tags": cluster.NodePoolAutoConfig.NetworkTags.Tags,
		}
		
		hclData["node_pool_auto_config"] = []map[string]interface{}{{
			"network_tags": []map[string]interface{}{networkTags},
		}}
	}

	// Set deletion protection to false by default
	hclData["deletion_protection"] = false
	
	// Check for incompatible configuration combinations and fix them
	validateAndFixHclData(hclData, isAutopilot)
	
	// Convert to CTY value with schema validation
	ctyVal, err := common.MapToCtyValWithSchema(hclData, c.schema)
	if err != nil {
		return nil, err
	}
	
	return &common.HCLResourceBlock{
		Labels: []string{c.name, cluster.Name},
		Value:  ctyVal,
	}, nil
}

// validateAndFixHclData validates and fixes potential conflicting configurations
// in the HCL data to ensure the generated Terraform configuration is valid.
func validateAndFixHclData(hclData map[string]interface{}, isAutopilot bool) {
	// 1. If enable_autopilot is true, we need to remove several fields that are
	// incompatible with Autopilot clusters
	if isAutopilot {
		// These fields are not applicable for Autopilot clusters
		incompatibleFields := []string{
			"node_config",
			"initial_node_count", 
			"node_locations",
			"node_pool",
			"remove_default_node_pool",
			"enable_kubernetes_alpha",
			"enable_legacy_abac",
			"cluster_autoscaling",
			"default_max_pods_per_node",
			"node_pool_auto_config",
		}
		
		for _, field := range incompatibleFields {
			delete(hclData, field)
		}
	}
	
	// 2. Ensure we're not using both old and new IP allocation fields
	if _, hasIpPolicy := hclData["ip_allocation_policy"]; hasIpPolicy {
		// If we have ip_allocation_policy, remove the old fields
		delete(hclData, "cluster_ipv4_cidr")
	}
	
	// 3. If there's an empty master_auth block, remove it
	if masterAuth, ok := hclData["master_auth"]; ok {
		if masterAuthList, ok := masterAuth.([]map[string]interface{}); ok && len(masterAuthList) > 0 {
			if len(masterAuthList[0]) == 0 {
				delete(hclData, "master_auth")
			}
		}
	}
	
	// 4. Handle enable_shielded_nodes vs shielded_instance_config
	// If node_config contains shielded_instance_config, we should not set enable_shielded_nodes
	if nodeConfig, ok := hclData["node_config"]; ok {
		if nodeConfigList, ok := nodeConfig.([]map[string]interface{}); ok && len(nodeConfigList) > 0 {
			if _, hasShielded := nodeConfigList[0]["shielded_instance_config"]; hasShielded {
				delete(hclData, "enable_shielded_nodes")
			}
		}
	}
}

// Helper functions to flatten nested structures
func flattenAddonsConfig(config *container.AddonsConfig) []map[string]interface{} {
	result := []map[string]interface{}{{}}
	
	if config.HorizontalPodAutoscaling != nil {
		result[0]["horizontal_pod_autoscaling"] = []map[string]interface{}{
			{"disabled": config.HorizontalPodAutoscaling.Disabled},
		}
	}
	
	if config.HttpLoadBalancing != nil {
		result[0]["http_load_balancing"] = []map[string]interface{}{
			{"disabled": config.HttpLoadBalancing.Disabled},
		}
	}
	
	if config.NetworkPolicyConfig != nil {
		result[0]["network_policy_config"] = []map[string]interface{}{
			{"disabled": config.NetworkPolicyConfig.Disabled},
		}
	}

	if config.GcpFilestoreCsiDriverConfig != nil {
		result[0]["gcp_filestore_csi_driver_config"] = []map[string]interface{}{
			{"enabled": !config.GcpFilestoreCsiDriverConfig.Disabled},
		}
	}

	if config.CloudRunConfig != nil {
		result[0]["cloudrun_config"] = []map[string]interface{}{
			{"disabled": config.CloudRunConfig.Disabled},
		}
	}

	if config.DnsCacheConfig != nil {
		result[0]["dns_cache_config"] = []map[string]interface{}{
			{"enabled": !config.DnsCacheConfig.Disabled},
		}
	}

	if config.GcsFuseCsiDriverConfig != nil {
		result[0]["gcs_fuse_csi_driver_config"] = []map[string]interface{}{
			{"enabled": !config.GcsFuseCsiDriverConfig.Disabled},
		}
	}
	
	return result
}

func flattenIPAllocationPolicy(policy *container.IPAllocationPolicy) []map[string]interface{} {
	result := map[string]interface{}{}

	if policy.ClusterSecondaryRangeName != "" {
		result["cluster_secondary_range_name"] = policy.ClusterSecondaryRangeName
	}

	if policy.ServicesSecondaryRangeName != "" {
		result["services_secondary_range_name"] = policy.ServicesSecondaryRangeName
	}

	if policy.ClusterIpv4CidrBlock != "" {
		result["cluster_ipv4_cidr_block"] = policy.ClusterIpv4CidrBlock
	}

	if policy.ServicesIpv4CidrBlock != "" {
		result["services_ipv4_cidr_block"] = policy.ServicesIpv4CidrBlock
	}

	if policy.UseRoutes {
		result["use_routes"] = policy.UseRoutes
	}

	// Only return the policy if we have at least one field set
	if len(result) > 0 {
		return []map[string]interface{}{result}
	}
	return nil
}

func flattenMasterAuth(auth *container.MasterAuth) []map[string]interface{} {
	result := map[string]interface{}{}
	
	if auth.ClientCertificateConfig != nil {
		result["client_certificate_config"] = []map[string]interface{}{
			{"issue_client_certificate": auth.ClientCertificateConfig.IssueClientCertificate},
		}
	}
	
	// We don't include username and password as they're sensitive
	// Also don't include client certificate data as it's sensitive
	
	// Only return the auth if we have client certificate config
	if len(result) > 0 {
		return []map[string]interface{}{result}
	}
	return nil
}

func flattenPrivateClusterConfig(config *container.PrivateClusterConfig) []map[string]interface{} {
	result := map[string]interface{}{
		"enable_private_endpoint": config.EnablePrivateEndpoint,
		"enable_private_nodes":    config.EnablePrivateNodes,
		"master_ipv4_cidr_block":  config.MasterIpv4CidrBlock,
	}

	if config.PrivateEndpoint != "" {
		result["private_endpoint"] = config.PrivateEndpoint
	}

	if config.PublicEndpoint != "" {
		result["public_endpoint"] = config.PublicEndpoint
	}

	return []map[string]interface{}{result}
}

func flattenNetworkPolicy(policy *container.NetworkPolicy) []map[string]interface{} {
	return []map[string]interface{}{{
		"enabled":  policy.Enabled,
		"provider": policy.Provider,
	}}
}

func flattenMasterAuthorizedNetworksConfig(config *container.MasterAuthorizedNetworksConfig) []map[string]interface{} {
	result := []map[string]interface{}{{
		"enabled": config.Enabled,
	}}
	
	if len(config.CidrBlocks) > 0 {
		cidrBlocks := make([]map[string]interface{}, len(config.CidrBlocks))
		for i, block := range config.CidrBlocks {
			cidrBlocks[i] = map[string]interface{}{
				"cidr_block":   block.CidrBlock,
				"display_name": block.DisplayName,
			}
		}
		result[0]["cidr_blocks"] = cidrBlocks
	}
	
	return result
}

func flattenNodeConfig(config *container.NodeConfig) []map[string]interface{} {
	result := map[string]interface{}{}

	if config.MachineType != "" {
		result["machine_type"] = config.MachineType
	}
	
	if config.DiskSizeGb > 0 {
		result["disk_size_gb"] = config.DiskSizeGb
	}
	
	if config.DiskType != "" {
		result["disk_type"] = config.DiskType
	}
	
	if config.ImageType != "" {
		result["image_type"] = config.ImageType
	}
	
	if len(config.Labels) > 0 {
		result["labels"] = config.Labels
	}
	
	if config.LocalSsdCount > 0 {
		result["local_ssd_count"] = config.LocalSsdCount
	}
	
	if len(config.Metadata) > 0 {
		result["metadata"] = config.Metadata
	}
	
	if config.MinCpuPlatform != "" {
		result["min_cpu_platform"] = config.MinCpuPlatform
	}
	
	if len(config.OauthScopes) > 0 {
		result["oauth_scopes"] = config.OauthScopes
	}
	
	result["preemptible"] = config.Preemptible
	
	if config.ServiceAccount != "" {
		result["service_account"] = config.ServiceAccount
	}
	
	if len(config.Tags) > 0 {
		result["tags"] = config.Tags
	}
	
	if len(config.Accelerators) > 0 {
		accelerators := make([]map[string]interface{}, len(config.Accelerators))
		for i, accelerator := range config.Accelerators {
			accelerators[i] = map[string]interface{}{
				"accelerator_count": accelerator.AcceleratorCount,
				"accelerator_type":  accelerator.AcceleratorType,
			}
		}
		result["guest_accelerator"] = accelerators
	}

	if config.ShieldedInstanceConfig != nil {
		result["shielded_instance_config"] = []map[string]interface{}{{
			"enable_secure_boot":          config.ShieldedInstanceConfig.EnableSecureBoot,
			"enable_integrity_monitoring": config.ShieldedInstanceConfig.EnableIntegrityMonitoring,
			"enable_vtpm":                 config.ShieldedInstanceConfig.EnableVtpm,
		}}
	}

	if config.BootDiskKmsKey != "" {
		result["boot_disk_kms_key"] = config.BootDiskKmsKey
	}

	if config.SandboxConfig != nil {
		result["sandbox_config"] = []map[string]interface{}{{
			"sandbox_type": config.SandboxConfig.Type,
		}}
	}

	if config.Reservation != "" {
		result["reservation_affinity"] = []map[string]interface{}{{
			"consume_reservation_type": "SPECIFIC_RESERVATION",
			"key":                      "compute.googleapis.com/reservation-name",
			"values":                   []string{config.Reservation},
		}}
	}
	
	if config.NodeGroup != "" {
		result["node_group"] = config.NodeGroup
	}

	if config.SoleTenantConfig != nil && len(config.SoleTenantConfig.NodeAffinity) > 0 {
		nodeAffinities := make([]map[string]interface{}, 0, len(config.SoleTenantConfig.NodeAffinity))
		for _, affinity := range config.SoleTenantConfig.NodeAffinity {
			if affinity.Key != "" && len(affinity.Values) > 0 {
				nodeAffinities = append(nodeAffinities, map[string]interface{}{
					"key":    affinity.Key,
					"values": affinity.Values,
				})
			}
		}
		
		if len(nodeAffinities) > 0 {
			result["sole_tenant_config"] = []map[string]interface{}{{
				"node_affinity": nodeAffinities,
			}}
		}
	}

	if config.KubeletConfig != nil {
		kubeletConfig := make(map[string]interface{})
		
		if config.KubeletConfig.CpuManagerPolicy != "" {
			kubeletConfig["cpu_manager_policy"] = config.KubeletConfig.CpuManagerPolicy
		}
		
		if config.KubeletConfig.CpuCfsQuota != nil {
			kubeletConfig["cpu_cfs_quota"] = config.KubeletConfig.CpuCfsQuota.Value
		}
		
		if config.KubeletConfig.CpuCfsQuotaPeriod != "" {
			kubeletConfig["cpu_cfs_quota_period"] = config.KubeletConfig.CpuCfsQuotaPeriod
		}
		
		if config.KubeletConfig.PodPidsLimit != nil {
			kubeletConfig["pod_pids_limit"] = config.KubeletConfig.PodPidsLimit.Value
		}
		
		if len(kubeletConfig) > 0 {
			result["kubelet_config"] = []map[string]interface{}{kubeletConfig}
		}
	}

	if config.LinuxNodeConfig != nil {
		linuxNodeConfig := make(map[string]interface{})
		
		if config.LinuxNodeConfig.Sysctls != nil {
			linuxNodeConfig["sysctls"] = config.LinuxNodeConfig.Sysctls
		}
		
		if len(linuxNodeConfig) > 0 {
			result["linux_node_config"] = []map[string]interface{}{linuxNodeConfig}
		}
	}

	if config.WorkloadMetadataConfig != nil && config.WorkloadMetadataConfig.Mode != "" {
		result["workload_metadata_config"] = []map[string]interface{}{{
			"mode": config.WorkloadMetadataConfig.Mode,
		}}
	}

	if config.Gcfs != nil {
		result["gcfs_config"] = []map[string]interface{}{{
			"enabled": config.Gcfs.Enabled,
		}}
	}

	if config.AdvancedMachineFeatures != nil {
		advFeatures := make(map[string]interface{})
		
		if config.AdvancedMachineFeatures.ThreadsPerCore != nil {
			advFeatures["threads_per_core"] = config.AdvancedMachineFeatures.ThreadsPerCore.Value
		}
		
		if len(advFeatures) > 0 {
			result["advanced_machine_features"] = []map[string]interface{}{advFeatures}
		}
	}

	if config.ConfidentialNodes != nil {
		result["confidential_nodes"] = []map[string]interface{}{{
			"enabled": config.ConfidentialNodes.Enabled,
		}}
	}
	
	if config.Spot {
		result["spot"] = config.Spot
	}
	
	if config.EffectiveTaints != nil && len(config.EffectiveTaints) > 0 {
		taints := make([]map[string]interface{}, 0, len(config.EffectiveTaints))
		for _, taint := range config.EffectiveTaints {
			taints = append(taints, map[string]interface{}{
				"key":    taint.Key,
				"value":  taint.Value,
				"effect": taint.Effect,
			})
		}
		result["taint"] = taints
	}
	
	return []map[string]interface{}{result}
}

func flattenReleaseChannel(channel *container.ReleaseChannel) []map[string]interface{} {
	if channel == nil || channel.Channel == "" {
		return nil
	}
	
	return []map[string]interface{}{{
		"channel": channel.Channel,
	}}
}

func flattenDatabaseEncryption(encryption *container.DatabaseEncryption) []map[string]interface{} {
	if encryption == nil {
		return nil
	}
	
	result := map[string]interface{}{
		"state": encryption.State,
	}
	
	if encryption.KeyName != "" {
		result["key_name"] = encryption.KeyName
	}
	
	return []map[string]interface{}{result}
}

func flattenClusterAutoscaling(autoscaling *container.ClusterAutoscaling) []map[string]interface{} {
	if autoscaling == nil {
		return nil
	}
	
	result := map[string]interface{}{
		"enabled": autoscaling.EnableNodeAutoprovisioning,
	}
	
	if len(autoscaling.ResourceLimits) > 0 {
		resourceLimits := make([]map[string]interface{}, 0, len(autoscaling.ResourceLimits))
		for _, limit := range autoscaling.ResourceLimits {
			resourceLimits = append(resourceLimits, map[string]interface{}{
				"resource_type": limit.ResourceType,
				"minimum":       limit.Minimum,
				"maximum":       limit.Maximum,
			})
		}
		result["resource_limits"] = resourceLimits
	}
	
	if autoscaling.AutoprovisioningNodePoolDefaults != nil {
		defaults := make(map[string]interface{})
		
		if autoscaling.AutoprovisioningNodePoolDefaults.OauthScopes != nil {
			defaults["oauth_scopes"] = autoscaling.AutoprovisioningNodePoolDefaults.OauthScopes
		}
		
		if autoscaling.AutoprovisioningNodePoolDefaults.ServiceAccount != "" {
			defaults["service_account"] = autoscaling.AutoprovisioningNodePoolDefaults.ServiceAccount
		}
		
		if autoscaling.AutoprovisioningNodePoolDefaults.DiskSizeGb != nil {
			defaults["disk_size"] = autoscaling.AutoprovisioningNodePoolDefaults.DiskSizeGb.Value
		}
		
		if autoscaling.AutoprovisioningNodePoolDefaults.DiskType != "" {
			defaults["disk_type"] = autoscaling.AutoprovisioningNodePoolDefaults.DiskType
		}
		
		if autoscaling.AutoprovisioningNodePoolDefaults.MinCpuPlatform != "" {
			defaults["min_cpu_platform"] = autoscaling.AutoprovisioningNodePoolDefaults.MinCpuPlatform
		}
		
		if len(defaults) > 0 {
			result["auto_provisioning_defaults"] = []map[string]interface{}{defaults}
		}
	}
	
	if autoscaling.AutoscalingProfile != "" {
		result["autoscaling_profile"] = autoscaling.AutoscalingProfile
	}
	
	return []map[string]interface{}{result}
}

func flattenBinaryAuthorization(ba *container.BinaryAuthorization) []map[string]interface{} {
	if ba == nil {
		return nil
	}
	
	result := map[string]interface{}{
		"enabled":         ba.Enabled,
		"evaluation_mode": ba.EvaluationMode,
	}
	
	if ba.PolicyBinding != nil && ba.PolicyBinding.Name != "" {
		result["policy_binding"] = []map[string]interface{}{{
			"name": ba.PolicyBinding.Name,
		}}
	}
	
	return []map[string]interface{}{result}
}