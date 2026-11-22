# AQX Community Compute — Security and Participation Specification

Status: **design specification only — not deployed or active**.

## 1. Purpose

AQX Community Compute may let consenting, registered AQX users contribute a tightly limited amount of their device capacity to approved AQX workloads. It is supplemental capacity only. AQX core services and review moderation must continue to work when every participant is offline or has opted out.

## 2. Eligibility and consent

- Registered accounts only. Guest sessions are never eligible.
- Participation must be explained in plain language before the first activation.
- Obtain an explicit, affirmative consent event before any device work begins. Do not pre-check consent or infer it from account creation.
- After consent, participation may remain enabled across sessions until the user turns it off.
- Provide a persistent, accessible on/off control in account settings.
- Turning participation off must stop accepting new tasks immediately and cancel or safely abandon queued work. Do not wait for a later session.
- Record consent version, timestamp, account ID, device installation ID, and subsequent opt-out timestamp. Do not store unnecessary device identifiers.
- If the policy materially changes, require renewed consent.

## 3. Default operating limits

Initial conservative eligibility rules for a future mobile client:

- Run only while the device is charging and connected to Wi-Fi.
- Pause when the operating system reports thermal pressure, low battery, low storage, or resource pressure.
- Respect OS background execution limits; never evade battery controls or keep hidden processes alive.
- Use a strict per-task CPU, memory, runtime, and network budget. Exact numeric limits must be established through real-device benchmarking before release; do not advertise untested figures.
- No cellular-data participation by default.
- No foreground interaction, notifications spam, or user-visible performance degradation.
- The OS and user controls always take precedence over AQX scheduling.

## 4. Permitted workloads

Only tasks that are safe to disclose to a participating device and can be independently validated may be distributed, for example:

- Public, synthetic, or explicitly de-identified test data.
- Benchmarking and regression tests using non-sensitive samples.
- Evaluation of public model outputs against non-private test cases.
- Deterministic, bounded batch tasks whose input and output are safe to expose to the device owner.

## 5. Prohibited workloads

Never send these to participant devices:

- Private reviews, unpublished ratings, messages, account data, credentials, tokens, or signed storage URLs.
- Personal data, sensitive personal data, private images, or private audio.
- Any moderation decision that directly publishes, rejects, suspends, or otherwise changes a user's content or account.
- Secrets, production database access, privileged API credentials, or unrestricted network requests.
- Arbitrary code supplied by another participant or an untrusted task submitter.

Private moderation remains inside AQX-controlled trusted infrastructure. Community devices must not become moderation authorities.

## 6. Task isolation and verification

Before production, the client and coordinator must implement:

- Signed task manifests, strict allowlisted task types, short expirations, replay protection, and per-account/device quotas.
- Sandboxed execution with no access to personal files, contacts, clipboard, microphone, camera, location, or unrelated apps.
- Network egress allowlists; no arbitrary outbound traffic.
- Input/output size limits, timeouts, memory/CPU budgets, and cancellation.
- Server-side validation of every result. Never trust a participant's self-reported result.
- Duplicate or independently sampled execution for tasks where correctness matters.
- Abuse detection, revocation, audit logs, and a kill switch that disables task issuance globally.
- No participant-to-participant access and no exposure of one participant's data to another.

## 7. Privacy and transparency

Explain what is computed, what data is sent, estimated resource use, and how to stop participation. Collect only the minimum operational telemetry needed for reliability and abuse prevention. Never sell participant data or use it for advertising.

## 8. Required acceptance tests before launch

1. Guest accounts cannot enroll or receive tasks.
2. A registered account receives no task before explicit consent.
3. Opt-out prevents new task assignment immediately and cancels queued work.
4. Opt-out persists across app restarts and account sessions.
5. No task contains private review content, user data, credentials, or signed URLs.
6. Thermal, battery, charging, Wi-Fi, and OS background constraints pause work correctly.
7. Expired, replayed, malformed, oversized, and unauthorized tasks are rejected.
8. Forged or inconsistent results cannot affect production data or moderation outcomes.
9. Global kill switch stops new task issuance.
10. Core AQX services remain operational with zero community participants.

## 9. Rollout gates

Do not activate production participation until AQX has a mobile client, authenticated coordinator, task sandbox, consent/settings UI, privacy notice, resource-budget measurements across representative devices, and passing security tests. Start with internal synthetic benchmarks, then a small opt-in pilot. Do not promise free or unlimited compute until measured capacity and operating costs support that claim.
