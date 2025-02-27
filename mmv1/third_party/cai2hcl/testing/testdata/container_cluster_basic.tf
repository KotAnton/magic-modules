resource "google_container_cluster" "test-cluster" {
  name                     = "test-cluster"
  location                 = "us-central1"
  description              = "GKE test cluster for cai2hcl conversion"
  initial_node_count       = 1
  node_locations           = ["us-central1-a", "us-central1-b", "us-central1-c"]
  network                  = "default"
  subnetwork               = "default"
  cluster_ipv4_cidr        = "10.52.0.0/14"
  deletion_protection      = false
  logging_service          = "logging.googleapis.com/kubernetes"
  monitoring_service       = "monitoring.googleapis.com/kubernetes"
  default_max_pods_per_node = 110

  addons_config {
    http_load_balancing {
      disabled = false
    }
    horizontal_pod_autoscaling {
      disabled = false
    }
    network_policy_config {
      disabled = true
    }
    gcp_filestore_csi_driver_config {
      enabled = true
    }
  }

  ip_allocation_policy {
    cluster_ipv4_cidr_block       = "10.52.0.0/14"
    services_ipv4_cidr_block      = "10.56.0.0/20"
    cluster_secondary_range_name  = "gke-test-cluster-pods-c889c44a"
    services_secondary_range_name = "gke-test-cluster-services-c889c44a"
  }

  master_authorized_networks_config {
    enabled = true
    cidr_blocks {
      cidr_block   = "10.0.0.0/8"
      display_name = "internal-network"
    }
    cidr_blocks {
      cidr_block   = "172.16.0.0/12"
      display_name = "vpn-network"
    }
  }

  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  node_config {
    machine_type = "e2-medium"
    disk_size_gb = 100
    disk_type    = "pd-standard"
    image_type   = "COS_CONTAINERD"
    oauth_scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/trace.append"
    ]
    service_account = "default"
    metadata = {
      "disable-legacy-endpoints" = "true"
    }
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
      enable_vtpm                 = true
    }
  }

  release_channel {
    channel = "REGULAR"
  }

  resource_labels = {
    environment = "development"
    created-by  = "terraform"
    team        = "platform"
  }

  database_encryption {
    state = "DECRYPTED"
  }
}