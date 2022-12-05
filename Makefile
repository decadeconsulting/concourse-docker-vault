.PHONY: setup clean dockerup restart dockerdown generate_concourse_keys generate_rootCA generate_concourse_cert generate_vault_cert generate_manager_cert generate_vault_config unseal vault_unseal vault_postsetup generate_vault_concourse_policy generate_vault_manager_policy info test testtask testtasksecure

# if setup generates new certs, you have to:
# a) also run make unseal
# b) if concourse web is running, restart it
# you also have to restart the web container if you alter the vault concourse policy
default: dockerup info

setup: generate_concourse_keys generate_rootCA generate_concourse_cert generate_vault_cert generate_manager_cert generate_vault_config

unseal: vault_unseal vault_postsetup generate_vault_concourse_policy generate_vault_manager_policy

dockerup:
	docker-compose up -d

restart:
	docker-compose restart

dockerdown:
	docker-compose down

########################
###  setup targets  ####
########################

generate_concourse_keys: ./keys/web/tsa_host_key ./keys/web/session_signing_key ./keys/web/authorized_worker_keys ./keys/web/tsa_host_key.pub ./keys/worker/worker_key ./keys/worker/worker_key.pub ./keys/worker/tsa_host_key.pub

./keys/web/tsa_host_key ./keys/web/session_signing_key ./keys/web/authorized_worker_keys ./keys/web/tsa_host_key.pub ./keys/worker/worker_key ./keys/worker/worker_key.pub ./keys/worker/tsa_host_key.pub:
	./keys/generate

generate_rootCA: certs/rootca.cert certs/rootca.csr certs/rootca.key certs/rootca.pem

certs/rootca.cert certs/rootca.csr certs/rootca.key certs/rootca.pem:
	./createCertificate.sh rootca concourse-docker-vault

generate_concourse_cert: certs/concourse/concourse.cert certs/concourse/concourse.csr certs/concourse/concourse.key certs/concourse/concourse.pem

certs/concourse/concourse.cert certs/concourse/concourse.csr certs/concourse/concourse.key certs/concourse/concourse.pem:
	./createCertificate.sh --destfolder certs/concourse --cafilebasename certs/rootca cert concourse 127.0.0.1

generate_vault_cert: certs/vault/vault.cert certs/vault/vault.csr certs/vault/vault.key certs/vault/vault.pem

certs/vault/vault.cert certs/vault/vault.csr certs/vault/vault.key certs/vault/vault.pem:
	./createCertificate.sh --destfolder certs/vault     --cafilebasename certs/rootca cert vault 127.0.0.1
	# cat certs/vault/vault.cert certs/rootca.cert > certs/vault/vault.pem

generate_manager_cert: certs/manager/manager.cert certs/manager/manager.csr certs/manager/manager.key certs/manager/manager.pem

certs/manager/manager.cert certs/manager/manager.csr certs/manager/manager.key certs/manager/manager.pem:
	./createCertificate.sh --destfolder certs/manager   --cafilebasename certs/rootca cert manager

generate_vault_config: ./certs/vault/vault.hcl

# tls_client_ca_file = 
# tls_cert_file = "/vault/config/server.crt"
# To configure the listener to use a CA certificate,
# concatenate the primary certificate and the CA certificate together.
# The primary certificate should appear first in the combined file
define HCL
ui = true
storage "file" {
	path = "/vault/file"
}
listener "tcp" {
	address = "0.0.0.0:8200"
	tls_disable = "false"
	tls_cert_file = "/vault/config/vault.cert"
	tls_key_file = "/vault/config/vault.key"
}
endef
export HCL

# config file does not necessarily be at this location
# but as we mount this path into the container anyway ...
./certs/vault/vault.hcl:
	echo "$$HCL" > $@

#########################
###  unseal targets  ####
#########################

keys/vault/vaultkeys.txt:
	VAULT_CACERT=certs/vault/vault.cert vault operator init | tee keys/vault/vaultkeys.txt

vault_unseal: keys/vault/vaultkeys.txt
	VAULT_CACERT=certs/vault/vault.cert vault operator unseal $$(grep 'Key 1:' keys/vault/vaultkeys.txt | awk '{print $NF}')
	VAULT_CACERT=certs/vault/vault.cert vault operator unseal $$(grep 'Key 2:' keys/vault/vaultkeys.txt | awk '{print $NF}')
	VAULT_CACERT=certs/vault/vault.cert vault operator unseal $$(grep 'Key 3:' keys/vault/vaultkeys.txt | awk '{print $NF}')

vault_postsetup:
	VAULT_TOKEN=$$(grep 'Initial Root Token:' keys/vault/vaultkeys.txt | awk '{print $$NF}') \
		vault secrets enable -tls-skip-verify -path=concourse -description="concourse CICD secrets" kv

# if the policy is altered also have to restart the vault and web container
generate_vault_concourse_policy: ./certs/vault/vault_concourse_policy.hcl
	VAULT_TOKEN=$$(grep 'Initial Root Token:' keys/vault/vaultkeys.txt | awk '{print $$NF}') \
		vault auth enable -tls-skip-verify cert
	VAULT_TOKEN=$$(grep 'Initial Root Token:' keys/vault/vaultkeys.txt | awk '{print $$NF}') \
		vault write -tls-skip-verify auth/cert/certs/concourse \
			policies=concourse \
			certificate=@certs/rootca.cert

define VAULT_CONCOURSE_POLICY
path "concourse/*" {
    policy = "read"
}
endef
export VAULT_CONCOURSE_POLICY

# policy file does not have to be inside the container at all
# but as we need a file to give to the vault 
./certs/vault/vault_concourse_policy.hcl:
	echo "$$VAULT_CONCOURSE_POLICY" > $@
	VAULT_TOKEN=$$(grep 'Initial Root Token:' keys/vault/vaultkeys.txt | awk '{print $$NF}') \
		vault policy write -tls-skip-verify concourse $@

# if the policy is altered also have to restart the vault and web container
generate_vault_manager_policy: ./certs/vault/vault_manager_policy.hcl
	### enable certificate based login
	# 'vault auth enable cert' already done for concourse policy above
	VAULT_TOKEN=$$(grep 'Initial Root Token:' keys/vault/vaultkeys.txt | awk '{print $$NF}') \
		vault write -tls-skip-verify auth/cert/certs/manager \
			policies=manager \
			certificate=@certs/rootca.cert
	### enable user/pass based login
	VAULT_TOKEN=$$(grep 'Initial Root Token:' keys/vault/vaultkeys.txt | awk '{print $$NF}') \
		vault auth enable -tls-skip-verify userpass
	VAULT_TOKEN=$$(grep 'Initial Root Token:' keys/vault/vaultkeys.txt | awk '{print $$NF}') \
		vault write -tls-skip-verify auth/userpass/users/manager \
			password=manager \
			policies=manager

define VAULT_MANAGER_POLICY
# Manage k/v secrets
path "concourse/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}
# Create and manage entities and groups
path "identity/*" {
  capabilities = [ "create", "read", "update", "delete", "list" ]
}
# Manage auth methods broadly across Vault
path "auth/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
# Create, update, and delete auth methods
path "sys/auth/*"
{
  capabilities = ["create", "update", "delete", "sudo"]
}
# List auth methods
path "sys/auth"
{
  capabilities = ["read"]
}
# Manage userpass auth methods
path "auth/userpass/*" {
  capabilities = [ "create", "read", "update", "delete" ]
}
# Create and manage ACL policies
path "sys/policies/acl/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
# To list policies
path "sys/policies/acl"
{
  capabilities = ["list"]
}
# Display the Policies tab in UI
path "sys/policies" {
  capabilities = [ "read", "list" ]
}
# Read default token configuration
path "sys/auth/token/tune" {
  capabilities = [ "read", "sudo" ]
}
# Create and manage tokens (renew, lookup, revoke, etc.)
path "auth/token/*" {
  capabilities = [ "create", "read", "update", "delete", "list", "sudo" ]
}
# Create and manage secrets engines broadly across Vault.
path "sys/mounts/*"
{
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
# List existing secrets engines.
path "sys/mounts"
{
  capabilities = ["read"]
}
# Read health checks
path "sys/health"
{
  capabilities = ["read", "sudo"]
}
path "sys/capabilities"
{
  capabilities = ["create", "update"]
}
path "sys/capabilities-self"
{
  capabilities = ["create", "update"]
}
endef
export VAULT_MANAGER_POLICY

./certs/vault/vault_manager_policy.hcl:
	echo "$$VAULT_MANAGER_POLICY" > $@
	VAULT_TOKEN=$$(grep 'Initial Root Token:' keys/vault/vaultkeys.txt | awk '{print $$NF}') \
		vault policy write -tls-skip-verify manager $@

#######################
###  test targets  ####
#######################

test: testtask testtasksecure

testtask:
	@echo ""
	@echo "executing task without secrets"
	fly --target local login --concourse-url http://localhost:8080 -u test -p test
	fly -t local execute -c test/task_hello_world.yml

testtasksecure:
	@echo ""
	@echo "executing task containing secrets"
	fly --target local login --concourse-url http://localhost:8080 -u test -p test
	VAULT_TOKEN=$$(grep 'Initial Root Token:' keys/vault/vaultkeys.txt | awk '{print $$NF}') \
		vault kv put concourse/main/testsecret value="$$(date)"
	fly -t local execute -c test/task_hello_world_secret.yml

#######################
###  misc targets  ####
#######################

clean:
	docker ps --all | grep concourse-docker-vault | awk '{print $$1}' | sed -e :a -e "\$$!N; s/\n/ /; ta" | xargs docker rm -f
	git check-ignore -v $$(find . -type f -print) | awk '{print $$2}' | xargs -I{} sh -c 'echo rm {} ; rm {}'

info:
	ls -l keys/* | sed -E '/^(total.*|.*generate)?$$/d' | awk '{print $$1 " " $$6 " " $$7 " " $$8 " " $$9}'
	docker ps --all

