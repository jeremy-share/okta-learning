auth:
	docker compose run -it --rm app

init:
	export $$(cat .env | xargs) && terraform init

plan:
	export $$(cat .env | xargs) && terraform plan

apply:
	export $$(cat .env | xargs) && terraform apply

apply-auto:
	export $$(cat .env | xargs) && terraform apply -auto-approve

refresh:
	export $$(cat .env | xargs) && terraform refresh
