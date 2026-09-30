---
name: alert-writing
description: Tone, structure, and safety rules for every piece of user-facing alert text Patchtacio produces (email, SMS, webhook, desktop notification, UI finding cards, CLI summaries), aimed at non-specialist IT staff in schools, councils, and small businesses. Use this whenever writing or changing templates in internal/advice/, notification formatting, or any wording that tells a user what to do about a vulnerability or end-of-life product.
---

# Writing alerts

Readers are busy, often not security specialists, and may read this on a phone. They must be able
to decide **what to do and by when** in under 30 seconds.

## Structure (email / UI card)

1. **Subject / headline:** `[Action needed by 14 Oct] FortiOS: actively exploited flaw`
   or `[End of life in 30 days] Windows Server 2016`
2. **What's affected:** product (+ version if the user gave one) and where they said it runs.
3. **Why it matters (1–2 sentences):** "Attackers are already using this. CISA added it to its
   exploited list on <date>." Add "Linked to ransomware campaigns." only if the KEV flag says so.
4. **What to do:** in order of preference:
   - **Patch:** "Update to <fixed version>". *Only if the version comes from source data.*
   - **Mitigate/disable:** from KEV `requiredAction` or the vendor advisory.
   - **If neither is possible:** "Disconnect or restrict access until you can patch."
5. **Links:** vendor advisory, KEV entry, CVE ID.
6. **Footer:** how to acknowledge (`patchtacio ack <id>` or UI button), and why they received it.

## Rules

- Plain English, short sentences. Explain jargon once or avoid it ("remote access (VPN)").
- **Never** say or imply "safe to ignore", "low risk", or "not affected" unless source data
  explicitly states it for their version.
- **Never invent** fixed versions, dates, or workarounds. Missing data → "Check the vendor
  advisory for the fixed version:" + link.
- Dates are absolute (`14 Oct 2026`), never "soon". Say when a due date has already passed.
- No fear-mongering, exclamation marks, or ALL CAPS beyond the bracketed tag.
- **SMS/push:** ≤ 160 characters: `Patchtacio: FortiOS exploited flaw CVE-XXXX-YYYY. Patch/disable SSL-VPN by 14 Oct. Details in email.`
- **End-of-life alerts:** state the date, what stops (security updates vs. all support), and the
  next supported version if endoflife.date lists one.

## Testing

Every template has golden-file tests covering: full data, missing fixed version, past due date,
ransomware flag, EOL already passed, and very long product names.
