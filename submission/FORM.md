# Submission form — ready-to-paste answers

The form lives in the submission panel at https://www.wemakedevs.org/hackathons/zerops
(it opens on the page itself; no external form). Deadline: Sunday, August 9, 2026 —
check the exact cutoff time on the page.

Fields the rules name: repository, live URL, demo, post, AI tools disclosure.
Forms usually also ask name/description/how-Zerops-is-used, so those are here too.

---

## Project name

Esclusa

## One-line description

A safety gate for AI agents that change infrastructure: agents ask first, every
decision is signed into a tamper-evident ledger, and the gate probes the private
network to catch what happened anyway.

## Repository

https://github.com/JuanMarchetto/esclusa

## Live deployment URL

https://console-2a56.prg1.zerops.app

(the console is the human surface; the gate API behind it is
https://gate-2a56-3000.prg1.zerops.app — both stay up through judging)

## Demo video

https://youtu.be/-iKw1haZ34E

(same file also lives in the repo at `submission/esclusa-demo.mp4`, and the
README links the YouTube URL near the top)

## Social post (link)

PENDING — publish first, then paste the URL of the post here.
The ready-to-paste text (X thread of 5 + LinkedIn variant, all required elements,
tags @WeMakeDevs @zeropsio) is in `submission/social-post.md`.

## How Zerops is used (short answer)

The mechanism depends on one platform property: every service in a Zerops project
sits on a private VXLAN with internal DNS, and the gate is on it too. That is what
lets it TCP-probe db, cache, and oldworker by hostname every 15 s from inside —
the reality check that turns "an agent skipped the gate" into a red drift alert.
On top of that: 7 services in one project, managed PostgreSQL (the HMAC-chained
ledger) and managed Valkey (rate limit shared across gate containers) wired with
cross-service env refs that resolve only inside containers, generated secrets at
import time, public subdomains for the browser demo, split build/run pipelines
per service, and a readiness check gating each deploy. A longer version is the
"How Zerops is used" section of the README.

## AI tools disclosure

Built with Claude Code (Anthropic): it drove implementation, code review, and
deployment, including multi-agent workflows for parallel build and adversarial
review. The author directed scope, design decisions, and priorities throughout.
(Same text as the README's "AI disclosure" section.)

## Team / builder

Solo build — Juan Marchetto.

---

## Before you press submit

1. Publish the social post (`submission/social-post.md`), copy its URL into the
   form's post field.
2. Spot-check the live console still answers: https://console-2a56.prg1.zerops.app
   (topology cards green, chain badge verified).
3. If a judge just ran scenario 2/3, oldworker may show red for ~90 s — that is
   the product working, not an outage.
