#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$script_dir/.." && pwd)
: "${IMAGE_URI:?IMAGE_URI is required}"
: "${ECR_REGISTRY:?ECR_REGISTRY is required}"
[[ "$IMAGE_URI" == "$ECR_REGISTRY/"* ]] || {
  echo 'IMAGE_URI must belong to the configured ECR registry.' >&2; exit 2;
}
work=$(mktemp -d "$repo/.scanner-work.XXXXXX")
source_root="$work/extracted-source"
mkdir "$source_root"
container_id=''
cleanup() {
  if [[ -n "$container_id" ]]; then docker rm -f "$container_id" >/dev/null; fi
}
trap cleanup EXIT

docker pull "$IMAGE_URI"
container_id=$(docker create "$IMAGE_URI")
# '/.' copies the directory contents directly; '/app/' would add an app folder.
container_source=${CONTAINER_SOURCE_PATH:-/app}
docker cp "$container_id:${container_source%/}/." "$source_root/"
docker rm "$container_id" >/dev/null
container_id=''

bash "$script_dir/scan-source.sh" "$source_root" "$work/analysis" "$repo/report.sarif"
