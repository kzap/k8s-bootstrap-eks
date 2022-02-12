variable "cluster_name" {
  type = string
}

variable "cluster_version" {
  type    = string
  default = "1.21"
}

variable "cluster_region" {
  type    = string
  default = "us-east-1"
}
