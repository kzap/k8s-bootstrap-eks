provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

################################################################################
# Cluster Autoscaler
# Based on the official docs at
# https://github.com/kubernetes/autoscaler/tree/master/cluster-autoscaler
################################################################################

resource "helm_release" "argocd" {
  name             = "argo-cd"
  namespace        = "argocd"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  version          = "3.33.5"
  create_namespace = true

  values = [
    "${file("helm/argo-cd/values.yaml")}"
  ]

  depends_on = [
    module.eks.cluster_id,
    null_resource.patch,
  ]
}
