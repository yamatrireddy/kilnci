<!-- SPDX-License-Identifier: Apache-2.0 -->
# Operating Kiln runners

A runner is a small agent (`kiln-runner`) that pulls jobs from the Kiln
server over mutual TLS and runs every step in a hardened Docker container
(ADR-0005, ADR-0006). Job code is untrusted: treat runner hosts as
disposable, dedicated machines.

## 1. Server side

```bash
kiln-server runner-ca init --dir /etc/kiln/runner-ca   # once; keep ca.key secret
export KILN_RUNNER_CA_DIR=/etc/kiln/runner-ca
export KILN_RUNNER_HOSTNAMES=runners.kiln.example.com  # names runners dial
export KILN_RUNNER_ADDR=:9443
```

`ca.key` must be readable only by the server (mode 0600); the server refuses
to start otherwise. Distribute `ca.crt` (public) to runner hosts.

## 2. Register a runner

An org admin creates a single-use registration token (labels and trust are
fixed by the token):

```bash
curl -X POST https://kiln.example.com/api/v1/orgs/acme/runner-registration-tokens \
  -H 'Content-Type: application/json' -H "X-CSRF-Token: …" --cookie … \
  -d '{"labels":["linux","amd64"],"trusted":false,"expiresInMinutes":30}'
```

On the runner host, pass the token through a file or stdin — never as a
command-line argument:

```bash
kiln-runner register --server runners.kiln.example.com:9443 \
  --ca-file ca.crt --token-file - --name builder-1 --state-dir /var/lib/kiln-runner <token.txt
```

The runner generates its own key (it never leaves the host), pins the CA,
and stores its certificate in the state directory. The state directory must
be a real directory (not a symlink), owned by the user the runner runs as,
with mode `0700`; the runner refuses to use it otherwise. On Windows,
restrict the directory's ACL to that user yourself. Certificates last 24
hours and are renewed automatically; if the state directory is copied to
another machine and both use it, the server detects the reuse and revokes
the runner.

**Trusted runners** (`"trusted": true`) never receive fork-PR jobs and are
the only runners that will receive secrets (Phase 2). Run them on separate
hosts from untrusted runners.

## 3. Block job egress to metadata and private networks

Job containers must not reach the cloud metadata service or internal
networks (threats T-20, T-21). Docker's `DOCKER-USER` chain filters traffic
from containers; add rules like these on every runner host (adjust the
private ranges to your network, and allow your registry and VCS):

```bash
# Cloud metadata (AWS/GCP/Azure/OCI) and link-local
iptables  -I DOCKER-USER -d 169.254.0.0/16 -j REJECT
ip6tables -I DOCKER-USER -d fd00:ec2::254/128 -j REJECT
# Private and CGNAT ranges (the runner host's own network included)
iptables  -I DOCKER-USER -d 10.0.0.0/8     -j REJECT
iptables  -I DOCKER-USER -d 172.16.0.0/12  -j REJECT
iptables  -I DOCKER-USER -d 192.168.0.0/16 -j REJECT
iptables  -I DOCKER-USER -d 100.64.0.0/10  -j REJECT
ip6tables -I DOCKER-USER -d fc00::/7       -j REJECT
# Keep established return traffic working
iptables  -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

On AWS, also require IMDSv2 with a hop limit of 1 and give runner instances
no IAM role that grants access to anything sensitive.

Then start the runner, acknowledging the policy:

```bash
kiln-runner run --state-dir /var/lib/kiln-runner --egress-policy host-enforced
```

`--egress-policy none` runs without these rules; every job log then starts
with a warning. Use it only for isolated development machines.

Image pulls are made by `dockerd` from the host's network, which the
`DOCKER-USER` rules above do not cover. The runner therefore refuses job
images from registries on loopback, private, link-local, CGNAT, or metadata
addresses (by literal address or by resolving the name; a name that does
not resolve is refused too). Allow an internal registry explicitly with
`--registry-allowlist registry.internal:5000,…` (exact `host[:port]`).
`dockerd` resolves the name again itself, and registry mirrors configured
on the daemon are not checked, so restrict `dockerd`'s own egress as well.

## 4. Limit job disk use

Each job's container writable layer and workspace volume are capped by
`--job-disk-limit` (default `10G`). Docker can only enforce this with the
`overlay2` storage driver on an XFS data root mounted with `pquota` (for
example `/var/lib/docker` on its own XFS filesystem with
`defaults,pquota`). The runner checks the driver at startup and before
each job, and refuses to run jobs otherwise; note that the containerd image
store, the default on new Docker installs, ignores the limit and is
refused. `--job-disk-limit=off` accepts unlimited disk use: a job can then
fill the Docker data root and break other jobs on the host. Keep the Docker
data root on a dedicated filesystem either way.

## 5. What the sandbox enforces

Each job gets its own bridge network (no inter-container traffic) and
workspace volume; the job container runs as UID 65532 (not a UID a person
on the host is likely to have; enable Docker's `userns-remap` to map it to
an unprivileged range as well) with all capabilities
dropped, `no-new-privileges`, the default seccomp/AppArmor profiles, an
init process, and limits (4 GiB memory without swap, 2 CPUs, 1024 PIDs,
disk as above). It never gets host namespaces, host mounts, `--privileged`,
or the Docker socket. Images are pulled anonymously for every job. The repository is
fetched at the exact commit by a separate clone container; the fetch
credential never reaches the job container and is masked in logs.
Everything is removed when the job ends.

Images must provide `/bin/sh`. Images that need root at build time must be
adapted (for example rootless BuildKit).

Revoke a runner with `DELETE /api/v1/orgs/{org}/runners/{id}`; it is cut off
on its next call, including a lease request already in progress.
