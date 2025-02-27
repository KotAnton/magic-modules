package container

import (
	"encoding/json"
	"testing"

	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/caiasset"
	"github.com/GoogleCloudPlatform/terraform-google-conversion/v6/cai2hcl/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	tpg_provider "github.com/hashicorp/terraform-provider-google-beta/google-beta/provider"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/container/v1"
)

func TestContainerClusterConverter_Convert(t *testing.T) {
	// Sample test cluster data
	cluster := &container.Cluster{
		Name:             "test-cluster",
		Location:         "us-central1",
		Description:      "Test GKE Cluster",
		InitialNodeCount: 3,
		Network:          "projects/test-project/global/networks/default",
		AddonsConfig: &container.AddonsConfig{
			HorizontalPodAutoscaling: &container.HorizontalPodAutoscaling{
				Disabled: false,
			},
			HttpLoadBalancing: &container.HttpLoadBalancing{
				Disabled: false,
			},
		},
		NodeConfig: &container.NodeConfig{
			MachineType:   "e2-medium",
			DiskSizeGb:    100,
			DiskType:      "pd-standard",
			ImageType:     "COS_CONTAINERD",
			Preemptible:   false,
			OauthScopes:   []string{"https://www.googleapis.com/auth/cloud-platform"},
		},
		ReleaseChannel: &container.ReleaseChannel{
			Channel: "REGULAR",
		},
	}

	// Create a sample asset
	clusterData, err := json.Marshal(cluster)
	if err != nil {
		t.Fatalf("Failed to marshal cluster data: %v", err)
	}

	asset := &caiasset.Asset{
		Name:      "//container.googleapis.com/projects/test-project/locations/us-central1/clusters/test-cluster",
		AssetType: ContainerClusterAssetType,
		Resource: &caiasset.Resource{
			Data: json.RawMessage(clusterData),
		},
	}

	// Create the converter
	provider := tpg_provider.Provider()
	converter := NewContainerClusterConverter(provider)

	// Convert the asset
	blocks, err := converter.Convert([]*caiasset.Asset{asset})
	if err != nil {
		t.Fatalf("Failed to convert asset: %v", err)
	}

	// Verify conversion results
	assert.Equal(t, 1, len(blocks), "Expected 1 resource block")
	assert.Equal(t, ContainerClusterSchemaName, blocks[0].Labels[0], "Expected resource type to be google_container_cluster")
	assert.Equal(t, "test-cluster", blocks[0].Labels[1], "Expected resource name to be test-cluster")
	
	// Generate HCL and verify it contains expected values
	hcl, err := common.HclWriteBlock(blocks[0])
	if err != nil {
		t.Fatalf("Failed to generate HCL: %v", err)
	}
	
	// Verify HCL contains essential attributes
	assert.Contains(t, string(hcl), "name = \"test-cluster\"")
	assert.Contains(t, string(hcl), "location = \"us-central1\"")
	assert.Contains(t, string(hcl), "initial_node_count = 3")
	assert.Contains(t, string(hcl), "description = \"Test GKE Cluster\"")
}

func TestContainerClusterConverter_ConvertComplex(t *testing.T) {
	// Sample cluster with more complex configurations
	cluster := &container.Cluster{
		Name:             "complex-cluster",
		Location:         "us-central1",
		Description:      "Complex GKE Cluster",
		InitialNodeCount: 1,
		Network:          "projects/test-project/global/networks/vpc-network",
		Subnetwork:       "projects/test-project/regions/us-central1/subnetworks/subnet-1",
		IpAllocationPolicy: &container.IPAllocationPolicy{
			ClusterSecondaryRangeName:  "pod-range",
			ServicesSecondaryRangeName: "svc-range",
		},
		PrivateClusterConfig: &container.PrivateClusterConfig{
			EnablePrivateNodes:    true,
			EnablePrivateEndpoint: false,
			MasterIpv4CidrBlock:   "172.16.0.0/28",
		},
		MasterAuthorizedNetworksConfig: &container.MasterAuthorizedNetworksConfig{
			Enabled: true,
			CidrBlocks: []*container.CidrBlock{
				{
					CidrBlock:   "10.0.0.0/8",
					DisplayName: "internal",
				},
			},
		},
		NodeConfig: &container.NodeConfig{
			MachineType:   "n1-standard-2",
			DiskSizeGb:    100,
			DiskType:      "pd-ssd",
			ImageType:     "COS_CONTAINERD",
			OauthScopes:   []string{"https://www.googleapis.com/auth/cloud-platform"},
			ShieldedInstanceConfig: &container.ShieldedInstanceConfig{
				EnableSecureBoot:          true,
				EnableIntegrityMonitoring: true,
				EnableVtpm:                true,
			},
		},
		ReleaseChannel: &container.ReleaseChannel{
			Channel: "STABLE",
		},
		DatabaseEncryption: &container.DatabaseEncryption{
			State:   "ENCRYPTED",
			KeyName: "projects/test-project/locations/us-central1/keyRings/ring/cryptoKeys/key",
		},
	}

	// Create a sample asset
	clusterData, err := json.Marshal(cluster)
	if err != nil {
		t.Fatalf("Failed to marshal cluster data: %v", err)
	}

	asset := &caiasset.Asset{
		Name:      "//container.googleapis.com/projects/test-project/locations/us-central1/clusters/complex-cluster",
		AssetType: ContainerClusterAssetType,
		Resource: &caiasset.Resource{
			Data: json.RawMessage(clusterData),
		},
	}

	// Create the converter
	provider := tpg_provider.Provider()
	converter := NewContainerClusterConverter(provider)

	// Convert the asset
	blocks, err := converter.Convert([]*caiasset.Asset{asset})
	if err != nil {
		t.Fatalf("Failed to convert asset: %v", err)
	}

	// Verify conversion results
	assert.Equal(t, 1, len(blocks), "Expected 1 resource block")
	
	// Generate HCL and verify it contains expected values
	hcl, err := common.HclWriteBlock(blocks[0])
	if err != nil {
		t.Fatalf("Failed to generate HCL: %v", err)
	}
	
	// Verify HCL contains complex configurations
	assert.Contains(t, string(hcl), "private_cluster_config {")
	assert.Contains(t, string(hcl), "enable_private_nodes = true")
	assert.Contains(t, string(hcl), "master_authorized_networks_config {")
	assert.Contains(t, string(hcl), "cidr_block = \"10.0.0.0/8\"")
	assert.Contains(t, string(hcl), "database_encryption {")
	assert.Contains(t, string(hcl), "state = \"ENCRYPTED\"")
	assert.Contains(t, string(hcl), "shielded_instance_config {")
	assert.Contains(t, string(hcl), "enable_secure_boot = true")
}

func TestContainerClusterConverter_ConvertAdvancedNodeConfig(t *testing.T) {
	// Cluster with advanced node configuration
	cluster := &container.Cluster{
		Name:             "advanced-node-config-cluster",
		Location:         "us-central1",
		Description:      "GKE Cluster with Advanced Node Configuration",
		InitialNodeCount: 1,
		Network:          "projects/test-project/global/networks/default",
		NodeConfig: &container.NodeConfig{
			MachineType:    "n1-standard-4",
			DiskSizeGb:     100,
			DiskType:       "pd-ssd",
			ServiceAccount: "test-sa@test-project.iam.gserviceaccount.com",
			Spot:           true,  // Use Spot VMs instead of preemptible
			BootDiskKmsKey: "projects/test-project/locations/us-central1/keyRings/ring/cryptoKeys/boot-key",
			Tags:           []string{"cluster-tag1", "cluster-tag2"},
			Labels: map[string]string{
				"env":  "test",
				"team": "platform",
			},
			WorkloadMetadataConfig: &container.WorkloadMetadataConfig{
				Mode: "GKE_METADATA",
			},
			SandboxConfig: &container.SandboxConfig{
				Type: "gvisor",
			},
			LinuxNodeConfig: &container.LinuxNodeConfig{
				Sysctls: map[string]string{
					"net.core.somaxconn":       "32768",
					"net.ipv4.tcp_tw_reuse":    "1",
					"net.ipv4.ip_local_port_range": "1024 65535",
				},
			},
			KubeletConfig: &container.NodeKubeletConfig{
				CpuManagerPolicy: "static",
				CpuCfsQuota: &container.BoolValue{
					Value: true,
				},
				CpuCfsQuotaPeriod: "100us",
				PodPidsLimit: &container.Int64Value{
					Value: 4096,
				},
			},
			AdvancedMachineFeatures: &container.AdvancedMachineFeatures{
				ThreadsPerCore: &container.Int64Value{
					Value: 2,
				},
			},
			EffectiveTaints: []*container.NodeTaint{
				{
					Key:    "special-node",
					Value:  "true",
					Effect: "NO_SCHEDULE",
				},
				{
					Key:    "dedicated",
					Value:  "gpu",
					Effect: "PREFER_NO_SCHEDULE",
				},
			},
			Gcfs: &container.Gcfs{
				Enabled: true,
			},
			Accelerators: []*container.AcceleratorConfig{
				{
					AcceleratorCount: 1,
					AcceleratorType:  "nvidia-tesla-t4",
				},
			},
		},
	}

	// Create a sample asset
	clusterData, err := json.Marshal(cluster)
	if err != nil {
		t.Fatalf("Failed to marshal cluster data: %v", err)
	}

	asset := &caiasset.Asset{
		Name:      "//container.googleapis.com/projects/test-project/locations/us-central1/clusters/advanced-node-config-cluster",
		AssetType: ContainerClusterAssetType,
		Resource: &caiasset.Resource{
			Data: json.RawMessage(clusterData),
		},
	}

	// Create the converter
	provider := tpg_provider.Provider()
	converter := NewContainerClusterConverter(provider)

	// Convert the asset
	blocks, err := converter.Convert([]*caiasset.Asset{asset})
	if err != nil {
		t.Fatalf("Failed to convert asset: %v", err)
	}

	// Verify conversion results
	assert.Equal(t, 1, len(blocks), "Expected 1 resource block")
	
	// Generate HCL and verify it contains expected values
	hcl, err := common.HclWriteBlock(blocks[0])
	if err != nil {
		t.Fatalf("Failed to generate HCL: %v", err)
	}
	
	// Verify HCL contains advanced node configurations
	assert.Contains(t, string(hcl), "node_config {")
	assert.Contains(t, string(hcl), "machine_type = \"n1-standard-4\"")
	assert.Contains(t, string(hcl), "boot_disk_kms_key = ")
	assert.Contains(t, string(hcl), "spot = true")
	assert.Contains(t, string(hcl), "sandbox_config {")
	assert.Contains(t, string(hcl), "sandbox_type = \"gvisor\"")
	assert.Contains(t, string(hcl), "workload_metadata_config {")
	assert.Contains(t, string(hcl), "mode = \"GKE_METADATA\"")
	assert.Contains(t, string(hcl), "linux_node_config {")
	assert.Contains(t, string(hcl), "kubelet_config {")
	assert.Contains(t, string(hcl), "advanced_machine_features {")
	assert.Contains(t, string(hcl), "taint {")
	assert.Contains(t, string(hcl), "effect = \"NO_SCHEDULE\"")
	assert.Contains(t, string(hcl), "gcfs_config {")
	assert.Contains(t, string(hcl), "guest_accelerator {")
}

func TestContainerClusterConverter_ConvertAutopilot(t *testing.T) {
	// Autopilot cluster
	cluster := &container.Cluster{
		Name:             "autopilot-cluster",
		Location:         "us-central1",
		Description:      "GKE Autopilot Cluster",
		Network:          "projects/test-project/global/networks/default",
		Subnetwork:       "projects/test-project/regions/us-central1/subnetworks/default",
		// Add fields that should be ignored in autopilot mode
		InitialNodeCount: 3,
		Locations:        []string{"us-central1-a", "us-central1-b"},
		NodeConfig: &container.NodeConfig{
			MachineType: "e2-standard-4", // This should be ignored
			DiskSizeGb:  100,             // This should be ignored
		},
		ClusterIpv4Cidr: "10.0.0.0/14", // This should be overridden by ip_allocation_policy
		Autopilot: &container.Autopilot{
			Enabled: true,
		},
		ReleaseChannel: &container.ReleaseChannel{
			Channel: "REGULAR",
		},
		IpAllocationPolicy: &container.IPAllocationPolicy{
			ClusterIpv4CidrBlock:    "10.100.0.0/14",
			ServicesIpv4CidrBlock:   "10.104.0.0/20",
			UseRoutes:               false,
		},
		EnableKubernetesAlpha: true, // Should be ignored for autopilot
		DefaultMaxPodsConstraint: &container.MaxPodsConstraint{
			MaxPodsPerNode: 110, // Should be ignored for autopilot
		},
		VerticalPodAutoscaling: &container.VerticalPodAutoscaling{
			Enabled: true,
		},
		DatabaseEncryption: &container.DatabaseEncryption{
			State: "DECRYPTED",
		},
		WorkloadIdentityConfig: &container.WorkloadIdentityConfig{
			WorkloadPool: "test-project.svc.id.goog",
		},
		MeshCertificates: &container.MeshCertificates{
			EnableCertificates: true,
		},
		NotificationConfig: &container.NotificationConfig{
			Pubsub: &container.PubSub{
				Enabled: true,
				Topic:   "projects/test-project/topics/gke-autopilot-notifications",
			},
		},
		NetworkConfig: &container.NetworkConfig{
			ServiceExternalIpsConfig: &container.ServiceExternalIPsConfig{
				Enabled: false,
			},
			DnsConfig: &container.DNSConfig{
				ClusterDns:       "CLOUD_DNS",
				ClusterDnsScope:  "CLUSTER_SCOPE",
				ClusterDnsDomain: "cluster.local",
			},
		},
	}

	// Create a sample asset
	clusterData, err := json.Marshal(cluster)
	if err != nil {
		t.Fatalf("Failed to marshal cluster data: %v", err)
	}

	asset := &caiasset.Asset{
		Name:      "//container.googleapis.com/projects/test-project/locations/us-central1/clusters/autopilot-cluster",
		AssetType: ContainerClusterAssetType,
		Resource: &caiasset.Resource{
			Data: json.RawMessage(clusterData),
		},
	}

	// Create the converter
	provider := tpg_provider.Provider()
	converter := NewContainerClusterConverter(provider)

	// Convert the asset
	blocks, err := converter.Convert([]*caiasset.Asset{asset})
	if err != nil {
		t.Fatalf("Failed to convert asset: %v", err)
	}

	// Verify conversion results
	assert.Equal(t, 1, len(blocks), "Expected 1 resource block")
	
	// Generate HCL and verify it contains expected values
	hcl, err := common.HclWriteBlock(blocks[0])
	if err != nil {
		t.Fatalf("Failed to generate HCL: %v", err)
	}
	
	// Verify HCL contains autopilot configurations
	assert.Contains(t, string(hcl), "enable_autopilot = true")
	assert.Contains(t, string(hcl), "ip_allocation_policy {")
	assert.Contains(t, string(hcl), "vertical_pod_autoscaling {")
	assert.Contains(t, string(hcl), "enabled = true")
	assert.Contains(t, string(hcl), "workload_identity_config {")
	assert.Contains(t, string(hcl), "workload_pool = \"test-project.svc.id.goog\"")
	assert.Contains(t, string(hcl), "mesh_certificates {")
	assert.Contains(t, string(hcl), "notification_config {")
	assert.Contains(t, string(hcl), "service_external_ips_config {")
	assert.Contains(t, string(hcl), "dns_config {")
	
	// Verify incompatible fields are NOT in the HCL
	assert.NotContains(t, string(hcl), "initial_node_count")
	assert.NotContains(t, string(hcl), "node_locations")
	assert.NotContains(t, string(hcl), "node_config")
	assert.NotContains(t, string(hcl), "cluster_ipv4_cidr")
	assert.NotContains(t, string(hcl), "enable_kubernetes_alpha")
	assert.NotContains(t, string(hcl), "default_max_pods_per_node")
}

func TestContainerClusterConverter_ConvertIpConfigurations(t *testing.T) {
	// Cluster with potentially conflicting IP configurations
	cluster := &container.Cluster{
		Name:             "ip-config-cluster",
		Location:         "us-central1",
		Description:      "GKE Cluster with IP Configurations",
		InitialNodeCount: 1,
		Network:          "projects/test-project/global/networks/default",
		Subnetwork:       "projects/test-project/regions/us-central1/subnetworks/default",
		// Legacy field that should be ignored when ip_allocation_policy is present
		ClusterIpv4Cidr: "10.0.0.0/14", 
		// Modern IP allocation policy
		IpAllocationPolicy: &container.IPAllocationPolicy{
			ClusterIpv4CidrBlock:       "10.100.0.0/14",
			ServicesIpv4CidrBlock:      "10.104.0.0/20",
			ClusterSecondaryRangeName:  "pods-range",
			ServicesSecondaryRangeName: "services-range",
			UseIpAliases:               true,
		},
	}

	// Create a sample asset
	clusterData, err := json.Marshal(cluster)
	if err != nil {
		t.Fatalf("Failed to marshal cluster data: %v", err)
	}

	asset := &caiasset.Asset{
		Name:      "//container.googleapis.com/projects/test-project/locations/us-central1/clusters/ip-config-cluster",
		AssetType: ContainerClusterAssetType,
		Resource: &caiasset.Resource{
			Data: json.RawMessage(clusterData),
		},
	}

	// Create the converter
	provider := tpg_provider.Provider()
	converter := NewContainerClusterConverter(provider)

	// Convert the asset
	blocks, err := converter.Convert([]*caiasset.Asset{asset})
	if err != nil {
		t.Fatalf("Failed to convert asset: %v", err)
	}

	// Verify conversion results
	assert.Equal(t, 1, len(blocks), "Expected 1 resource block")
	
	// Generate HCL and verify it contains expected values
	hcl, err := common.HclWriteBlock(blocks[0])
	if err != nil {
		t.Fatalf("Failed to generate HCL: %v", err)
	}
	
	// Verify HCL contains the newer IP allocation policy
	assert.Contains(t, string(hcl), "ip_allocation_policy {")
	assert.Contains(t, string(hcl), "cluster_ipv4_cidr_block = \"10.100.0.0/14\"")
	assert.Contains(t, string(hcl), "services_ipv4_cidr_block = \"10.104.0.0/20\"")
	assert.Contains(t, string(hcl), "cluster_secondary_range_name = \"pods-range\"")
	assert.Contains(t, string(hcl), "services_secondary_range_name = \"services-range\"")
	
	// Verify the legacy field is not present to avoid conflicts
	assert.NotContains(t, string(hcl), "cluster_ipv4_cidr = \"10.0.0.0/14\"")
}

func TestContainerClusterConverter_ConvertEmptyMasterAuth(t *testing.T) {
	// Cluster with empty master_auth
	cluster := &container.Cluster{
		Name:             "empty-master-auth-cluster",
		Location:         "us-central1",
		InitialNodeCount: 1,
		Network:          "projects/test-project/global/networks/default",
		MasterAuth:       &container.MasterAuth{}, // Empty master auth
	}

	// Create a sample asset
	clusterData, err := json.Marshal(cluster)
	if err != nil {
		t.Fatalf("Failed to marshal cluster data: %v", err)
	}

	asset := &caiasset.Asset{
		Name:      "//container.googleapis.com/projects/test-project/locations/us-central1/clusters/empty-master-auth-cluster",
		AssetType: ContainerClusterAssetType,
		Resource: &caiasset.Resource{
			Data: json.RawMessage(clusterData),
		},
	}

	// Create the converter
	provider := tpg_provider.Provider()
	converter := NewContainerClusterConverter(provider)

	// Convert the asset
	blocks, err := converter.Convert([]*caiasset.Asset{asset})
	if err != nil {
		t.Fatalf("Failed to convert asset: %v", err)
	}

	// Verify conversion results
	assert.Equal(t, 1, len(blocks), "Expected 1 resource block")
	
	// Generate HCL and verify it contains expected values
	hcl, err := common.HclWriteBlock(blocks[0])
	if err != nil {
		t.Fatalf("Failed to generate HCL: %v", err)
	}
	
	// Verify empty master_auth is not included
	assert.NotContains(t, string(hcl), "master_auth {")
}

func TestContainerClusterConverter_ConvertClusterAutoscaling(t *testing.T) {
	// Cluster with autoscaling configuration
	cluster := &container.Cluster{
		Name:             "autoscaling-cluster",
		Location:         "us-central1",
		Description:      "GKE Cluster with Autoscaling",
		InitialNodeCount: 1,
		Network:          "projects/test-project/global/networks/default",
		Autoscaling: &container.ClusterAutoscaling{
			EnableNodeAutoprovisioning: true,
			AutoscalingProfile:        "OPTIMIZE_UTILIZATION",
			ResourceLimits: []*container.ResourceLimit{
				{
					ResourceType: "cpu",
					Minimum:      1,
					Maximum:      32,
				},
				{
					ResourceType: "memory",
					Minimum:      1,
					Maximum:      64,
				},
				{
					ResourceType: "ephemeral-storage",
					Maximum:      100,
				},
			},
			AutoprovisioningNodePoolDefaults: &container.AutoprovisioningNodePoolDefaults{
				OauthScopes:    []string{"https://www.googleapis.com/auth/cloud-platform"},
				ServiceAccount: "sa-autoprovisioning@test-project.iam.gserviceaccount.com",
				DiskType:       "pd-standard",
				DiskSizeGb: &container.Int64Value{
					Value: 100,
				},
				MinCpuPlatform: "Intel Skylake",
			},
		},
		BinaryAuthorization: &container.BinaryAuthorization{
			Enabled:         true,
			EvaluationMode:  "PROJECT_SINGLETON_POLICY_ENFORCE",
		},
	}

	// Create a sample asset
	clusterData, err := json.Marshal(cluster)
	if err != nil {
		t.Fatalf("Failed to marshal cluster data: %v", err)
	}

	asset := &caiasset.Asset{
		Name:      "//container.googleapis.com/projects/test-project/locations/us-central1/clusters/autoscaling-cluster",
		AssetType: ContainerClusterAssetType,
		Resource: &caiasset.Resource{
			Data: json.RawMessage(clusterData),
		},
	}

	// Create the converter
	provider := tpg_provider.Provider()
	converter := NewContainerClusterConverter(provider)

	// Convert the asset
	blocks, err := converter.Convert([]*caiasset.Asset{asset})
	if err != nil {
		t.Fatalf("Failed to convert asset: %v", err)
	}

	// Verify conversion results
	assert.Equal(t, 1, len(blocks), "Expected 1 resource block")
	
	// Generate HCL and verify it contains expected values
	hcl, err := common.HclWriteBlock(blocks[0])
	if err != nil {
		t.Fatalf("Failed to generate HCL: %v", err)
	}
	
	// Verify HCL contains autoscaling configurations
	assert.Contains(t, string(hcl), "cluster_autoscaling {")
	assert.Contains(t, string(hcl), "enabled = true")
	assert.Contains(t, string(hcl), "autoscaling_profile = \"OPTIMIZE_UTILIZATION\"")
	assert.Contains(t, string(hcl), "resource_limits {")
	assert.Contains(t, string(hcl), "resource_type = \"cpu\"")
	assert.Contains(t, string(hcl), "auto_provisioning_defaults {")
	assert.Contains(t, string(hcl), "binary_authorization {")
	assert.Contains(t, string(hcl), "enabled = true")
}