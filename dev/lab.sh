#!/bin/sh
# Throwaway lab: a kind cluster with trivy-operator and trivyal from the
# local image. Needs docker and helm; kind runs through `go run`.
#
#   dev/lab.sh up     create the cluster, install everything
#   dev/lab.sh down   delete the cluster
set -eu

CLUSTER=trivyal-lab
KIND="go run sigs.k8s.io/kind@v0.33.0"
CTX="kind-$CLUSTER"
cd "$(dirname "$0")/.."
# A separate kubeconfig, so the lab never changes your current context.
export KUBECONFIG="$PWD/dev/lab.kubeconfig"

case "${1:-up}" in
up)
	if ! $KIND get clusters | grep -qx "$CLUSTER"; then
		$KIND create cluster --name "$CLUSTER" --wait 120s
	fi
	helm repo add aqua https://aquasecurity.github.io/helm-charts/ >/dev/null 2>&1 || true
	helm repo update aqua >/dev/null
	helm upgrade --install trivy-operator aqua/trivy-operator --kube-context "$CTX" \
		-n trivy-system --create-namespace \
		--set operator.sbomGenerationEnabled=true \
		--set compliance.cron="*/30 * * * *" \
		--wait
	# Something with known vulnerabilities to scan.
	kubectl --context "$CTX" create namespace demo --dry-run=client -o yaml | kubectl --context "$CTX" apply -f -
	kubectl --context "$CTX" -n demo create deployment web --image=nginx:1.25.0 --dry-run=client -o yaml |
		kubectl --context "$CTX" apply -f -
	docker build -t trivyal:lab .
	$KIND load docker-image trivyal:lab --name "$CLUSTER"
	helm upgrade --install trivyal charts/trivyal --kube-context "$CTX" -n trivy-system \
		--set image.repository=trivyal --set image.tag=lab --set image.pullPolicy=Never --wait
	echo
	echo "Reports appear after a few minutes. Open the UI with:"
	echo "  KUBECONFIG=dev/lab.kubeconfig kubectl -n trivy-system port-forward svc/trivyal 8080:80"
	;;
down)
	$KIND delete cluster --name "$CLUSTER"
	;;
*)
	echo "usage: $0 up|down" >&2
	exit 2
	;;
esac
