resource "aws_acm_certificate" "prod_api" {
  domain_name       = "api.internal.example"
  validation_method = "DNS"
  key_algorithm     = "RSA_2048"
}

resource "tls_private_key" "vpn" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "aws_iam_server_certificate" "legacy" {
  name             = "legacy-rsa-cert"
  certificate_body = file("certificates/prod_api.pem")
  private_key      = file("certificates/prod_api_rsa_private_key.pem")
}
