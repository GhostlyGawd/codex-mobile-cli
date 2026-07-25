# Cost model

Research date: 2026-07-15. Region assumption: United States East. All figures are before applicable tax unless stated otherwise.

> **Purchase status: OWNER-GATED — NOT AUTHORIZED.** No VPS has been purchased. The final owner-region checkout must be revalidated immediately before the owner explicitly approves a purchase.

## Hard contract

The only new recurring bill may be one fixed-price, month-to-month VPS between USD $25 and $75 before tax. It must include at least 8 shared vCPUs, 24 GiB RAM, 200 GB NVMe storage, enough transfer that usage cannot create an automatic overage, and a provider-native daily whole-server or volume backup. There may be no annual commitment or prepayment, metered compute, automatic scaling, paid usage overage, automatic top-up, or second paid recurring service. Under this fixed-cost contract the included whole-server backup is an availability/RPO control: it is expected to contain both encrypted application data and the root-owned host master key, so it provides no cryptographic separation from provider or full-backup compromise.

Existing ChatGPT, GitHub, owner-controlled domain, and Apple Developer Program
access are outside this VPS limit. Paid GitHub Actions overages remain
forbidden. Public CI uses only standard GitHub-hosted Linux and macOS runners,
which GitHub documents as free for public repositories. Every job also requires
public visibility and the explicit `PUBLIC_CI_ENABLED` variable; larger runners
and persistent owner-PC runners are prohibited.

## Research outcome

- **Sole qualifying recommendation on published US terms:** OVHcloud US `VPS-4 2027` in `US-EAST-VA`.
- **Required second qualifying plan:** not found. Several apparent matches have an overage clause, a separately paid backup, metered billing, the wrong currency or commitment, conflicting specifications, or an incomplete checkout contract.
- **Purchase remains blocked on owner action:** the owner must review and explicitly approve the final checkout after the checks below. No provider create, resize, or purchase API may be called automatically.

Detailed provider evidence and rejected candidates are recorded in [docs/research/2026-07-15-vps.md](docs/research/2026-07-15-vps.md).

## Recommended VPS

| Field | Verified value |
| --- | --- |
| Provider and plan | OVHcloud US, `VPS-4 2027` (`vps-2027-model4`) |
| Region | `US-EAST-VA` recommended; `US-WEST-OR` also appears in the live US catalog |
| Base recurring price | $27.50 USD/month in `default` mode |
| Commitment | 0; one-month interval, renewing month to month |
| Setup fee | $0.00 |
| Linux selection | $0.00 |
| Local NVMe storage selection | $0.00 |
| Standard automatic backup | Nominally $1.20/month, currently discounted 100% to $0.00 with no catalog end date; OVH also describes it as included |
| Exact published recurring total | **$27.50 USD/month before applicable tax** |
| Compute | 8 vCore |
| Memory | 24 GB as advertised; see GiB caveat below |
| Storage | 200 GB SSD NVMe |
| Transfer | Unlimited traffic in US regions, up to 3 Gbps; OVH states no extra traffic cost |
| Backup | Automatic daily backup of the previous 24 hours |
| Root access | Included |

Official evidence: [US VPS page](https://us.ovhcloud.com/vps/), [developer VPS page](https://us.ovhcloud.com/vps/vps-developers/), [Intel VPS details](https://us.ovhcloud.com/vps/vps-intel/), [backup options](https://www.ovhcloud.com/en/vps/options/), and [live US public order catalog](https://api.us.ovhcloud.com/1.0/order/catalog/public/vps?ovhSubsidiary=US).

The `$23.37/month` headline is not the approved price. OVH's order catalog identifies it as the effective price for a 12-month upfront commitment. The compliant mode is the zero-commitment `$27.50/month` default mode.

### Caveats and mandatory checkout revalidation

1. OVH advertises `24 GB` RAM while the project target is `24 GiB`. Provider marketing commonly labels binary-sized VM memory as GB, but the owner must obtain confirmation or accept a post-provision measurement gate; this document does not silently treat the units as identical.
2. The required Standard backup is currently reduced from $1.20 to $0 by a 100% catalog promotion with no listed end date. The public product pages independently call the daily backup included, but its `$0` final line must still be checked immediately before purchase.
3. Applicable sales tax depends on the owner's billing address and cannot be calculated without entering owner data. The approved pre-tax ceiling remains $75.
4. Confirm the final cart says `US-EAST-VA`, `default`/monthly, commitment `0`, setup `$0`, Linux `$0`, local NVMe storage `$0`, Standard automatic backup `$0`, and total `$27.50 + applicable tax`.
5. Reject the cart if it introduces a paid Premium backup, snapshot, additional disk, control-panel license, Windows license, annual term, automatic upgrade, or any usage-priced option.

## Candidate comparison

| Candidate | Published monthly figure | Result |
| --- | ---: | --- |
| OVHcloud US VPS-4 2027 | $27.50 | Sole published-term match; recommended subject to the owner gate and caveats above |
| SERVER1.GE Managed VPS B | $58.50 | Apparent resource/backup match, but official traffic policy permits an additional fee after notice; Canada location and managed root access are also unresolved |
| SERVER1.GE Managed VPS A | $73.30 | Same unresolved overage, location, and root-access conflicts |
| Cloudzy 24 GB VPS | $69.97 promotional | Pay-for-use/hourly model, temporary discount against a $139.95 list price, and free manual snapshots rather than an included daily server backup |
| DaManager VPS Macro | $60.00 | Backup inclusion and NVMe specification conflict across official pages; terms permit bandwidth-overage billing |
| Abhax VPS-3 / VPS-4 | $30.77 / $53.52 | Checkout resources conflict with the provider's main site; region and enforceable transfer terms are not established |
| Other checked providers | varies | Failed price, resource, currency, commitment, backup, or billing-model requirements; see the detailed research record |

Because no second plan conclusively passes every condition, this comparison is not permission to purchase. It is an evidence-backed recommendation to revalidate OVH and an explicit record of the remaining market constraint.

## Itemized recurring services

| Item | New recurring cost | Billing status | Enforcement |
| --- | ---: | --- | --- |
| OVHcloud VPS-4 2027, if owner-approved | $27.50/month before tax | Owner-gated; not purchased | Manual checkout review and explicit owner approval |
| PostgreSQL | $0 | Local container on VPS | Compose policy |
| Coder Community | $0 | Self-hosted community features only | Version/license pin and feature policy |
| Caddy/TLS | $0 | Self-hosted plus ACME | Compose policy |
| Provider backup | $0 additional | Must remain included in VPS checkout | Pre-purchase and post-deploy restore checks; availability/RPO only, because a whole-server capture includes the host key with encrypted data |
| Local checkpoints | $0 additional | VPS local disk | Quota and pruning policy |
| APNs | $0 additional | Existing Apple Developer access | Direct control-plane delivery |
| GitHub/CI | $0 additional | Existing account plus standard hosted runners for the public repository; paid overages forbidden | Public-visibility and explicit-variable gate; immutable Action SHAs; standard-runner policy; concurrency/timeouts |
| Monitoring/logging | $0 | Local only | No external exporters by default |
| Secrets/auth/cache/queues | $0 | In-process, PostgreSQL, and local files | Dependency and deployment policy tests |

## External and billable mutation gate

Repository automation may configure an existing owner-supplied host, but it must not create, purchase, resize, upgrade, or attach paid provider resources. Before purchase, show the owner the final provider, plan, region, monthly commitment, setup fee, tax, backup line, transfer policy, and recurring total. Continue only after explicit owner approval.

## Policy test

`scripts/check-billing-policy.*` rejects known managed databases, object stores, hosted auth, external observability, tunnels, serverless or metered compute, autoscaling, paid CI flags, and more than the approved Compose services. The test is a guardrail, not a substitute for reviewing provider checkout terms.
