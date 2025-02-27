resource "google_container_cluster" "autopilot-cluster" {
  name                     = "autopilot-cluster"
  location                 = "us-central1"
  description              = "GKE Autopilot cluster for cai2hcl conversion"
  network                  = "default"
  subnetwork               = "default"
  deletion_protection      = false
  logging_service          = "logging.googleapis.com/kubernetes"
  monitoring_service       = "monitoring.googleapis.com/kubernetes"
  enable_autopilot         = true

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
    dns_cache_config {
      enabled = true
    }
    gcs_fuse_csi_driver_config {
      enabled = true
    }
  }

  ip_allocation_policy {
    cluster_ipv4_cidr_block  = "10.100.0.0/14"
    services_ipv4_cidr_block = "10.104.0.0/20"
  }

  master_authorized_networks_config {
    enabled = true
    cidr_blocks {
      cidr_block   = "10.0.0.0/8"
      display_name = "internal-network"
    }
  }

  release_channel {
    channel = "REGULAR"
  }

  vertical_pod_autoscaling {
    enabled = true
  }

  workload_identity_config {
    workload_pool = "test-project.svc.id.goog"
  }

  mesh_certificates {
    enable_certificates = true
  }

  notification_config {
    pubsub {
      enabled = true
      topic   = "projects/test-project/topics/gke-notifications"
    }
  }

  service_external_ips_config {
    enabled = false
  }

  dns_config {
    cluster_dns        = "CLOUD_DNS"
    cluster_dns_scope  = "CLUSTER_SCOPE"
    cluster_dns_domain = "cluster.local"
  }

  cost_management_config {
    enabled = true
  }

  resource_labels = {
    environment = "development"
    created-by  = "terraform"
    managed-by  = "autopilot"
  }

  database_encryption {
    state = "DECRYPTED"
  }
}