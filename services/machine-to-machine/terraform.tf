terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
  required_providers {
    okta = {
      source = "okta/okta"
      version = "4.8.0"
    }
  }
}

provider "okta" {}

resource "okta_group" "example-group" {
  name = "example-group-1234"
}
