## Phishing Email Forensics

A single-sample case study of a UK "TV Licensing" payment phishing email: header and authentication analysis, obfuscation techniques, social engineering, indicators of compromise (IOCs), and a proposed detection rule.

> **Defanging note:** All domains, URLs and IP addresses in this report are defanged (`hxxps://`, `[.]`) so they cannot be clicked or resolved by accident. The email was handled as static text only. No links were opened and nothing was executed.
> 

## 1. Objective

Examine a real phishing email to:

- Analyse its SPF, DKIM and DMARC results and its Received chain
- Identify sender impersonation and technical concealment
- Extract IOCs
- Identify the social engineering techniques used


## 2. Scope and tools

This write-up covers **one sample** in depth. The aim is a thorough, evidence-based analysis of a single message, including the point that it passes all email authentication checks.

| Item | Detail |
| --- | --- |
| Sample | `.eml` file from a personal inbox (sanitised copy in `samples/`) |
| Tools | MXToolbox Email Header Analyzer, urlscan.io, VirusTotal (see section 5.2), text editor |
| Handling | Static analysis only. Links were never visited and no attachments were present. |

**Email subject** (contains look-alike Unicode characters, see section 4.3):

```
Third Not𝗂ce: L𝗂c𝖾nce Fee O𝗎tst𝖺nding — Avo𝗂d Εnforcement Act𝗂on - JE2LR
```

## 3. Methodology

1. **Raw source review:** read the headers, subject, plain-text part and HTML part.
2. **Authentication:** recorded SPF, DKIM and DMARC results from the headers and MXToolbox.
3. **Sender analysis:** compared the display name, From address, Reply-To and Return-Path.
4. **Received chain:** traced the routing to identify the sending infrastructure.
5. **Obfuscation analysis:** examined MIME encoding, Unicode characters and HTML/CSS.
6. **URL analysis:** extracted every link and compared destinations; scanned the URL in urlscan.io.
7. **IOC extraction:** recorded domains, IPs, URLs and other identifiers.


## 4. Findings

**Assessment: high-confidence phishing.**

The email impersonates TV Licensing and claims the recipient has an outstanding licence fee. It threatens enforcement action and a £1,000 fine, and pushes the recipient to pay or update payment details through embedded links.

### 4.1 Email authentication

| Check | Result | What it tells us |
| --- | --- | --- |
| SPF | PASS | The sending server is authorised to send for the sender domain. |
| DKIM | PASS | The message was signed by the signing domain and the signed content was not altered. |
| DMARC | PASS | SPF or DKIM aligned with the domain in the From address. |
| Return-Path vs From | Match (same domain) | Both use `kneesway[.]hiddenlakeswinery[.]com`. Neither is a TV Licensing domain. |

**Interpretation:** a full authentication pass does *not* mean the email is legitimate. SPF, DKIM and DMARC proved the message came from `kneesway[.]hiddenlakeswinery[.]com`. They say nothing about whether that domain has any connection to TV Licensing. Attackers can send fully authenticated mail from domains or accounts they control.

### 4.2 Sender and Received chain

| Header | Observed value |
| --- | --- |
| Display name | `TV LICENSING UK #62781` |
| From | `television-uk-mail-supports-3215584@kneesway[.]hiddenlakeswinery[.]com` |
| Reply-To | `noreply@kneesway[.]hiddenlakeswinery[.]com` |
| Return-Path | Address on `kneesway[.]hiddenlakeswinery[.]com` |
| To | `noreply@tvlicense[.]co[.]uk` |
| BCC | `target@email.com` (sanitised placeholder) |
| Sending IP | `74[.]125[.]229[.]4` |
| HELO | `mail-dy2-f4[.]google[.]com` |
| Message-ID domain | `mail[.]gmail[.]com` |

**Key observations**

- The display name claims to be TV Licensing, but the actual address is on an unrelated domain. The Reply-To uses the same domain.
- The recipient is hidden in BCC while the To field holds a "noreply" address, a common bulk-mailing pattern.
- The Received chain points to Google infrastructure. The sending IP belongs to shared Google mail servers, so **it should not be treated as an IOC for blocking** without more context.
- One header reads `Received: from 1044537094479 named unknown by gmailapi.google.com with HTTPREST`, which suggests the message was submitted through the Gmail API. The headers do not show who controlled the submitting account or how they got access.

### 4.3 Obfuscation and concealment

The sender used several techniques to defeat keyword filters and text extraction. This is obfuscation, not strong encryption.

**Look-alike characters in the subject.** Letters such as `i`, `e`, `u` and `a` are replaced with mathematical sans-serif variants, and the leading `E` of "Enforcement" is a Greek capital epsilon. The words look normal to a reader but have different underlying code points, so simple keyword matches miss them.

**Invisible Unicode characters in the body.** Many zero-width and formatting characters are inserted into ordinary words:

| Code point | Name |
| --- | --- |
| U+034F | Combining grapheme joiner |
| U+200C | Zero-width non-joiner |
| U+200D | Zero-width joiner |
| U+2060 | Word joiner |
| U+2061 | Function application (invisible operator) |
| U+206B | Activate symmetric swapping (deprecated bidi format character) |
| U+FE0E | Variation selector-15 (text presentation) |
| U+FE0F | Variation selector-16 (emoji presentation) |

**HTML/CSS manipulation.** The HTML defines classes with zero font size, zero line height, hidden overflow and transparent text, which can hide content from readers while leaving it in the source. The source does not confirm that every defined class is applied to hidden content, so this is treated as suspicious rather than proven.

**URL indirection.** All calls to action point to one Google-hosted URL (see section 4.4).

**Cryptography in the headers is not encryption of the message.** The DKIM and ARC headers use `a=rsa-sha256`. RSA signatures with SHA-256 prove authenticity and integrity, not confidentiality. The headers also show the TLS cipher suite `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, which is transport encryption between mail servers. There is no evidence of PGP, S/MIME or any other end-to-end encryption.

### 4.4 Links

Every call to action uses the same destination:

- Pay Now
- Update Payment Details
- Change Payment Plan
- Confirm that no licence is required
- Privacy and terms links

```
hxxps://google[.]com/share[.]google?q=0myWDVBTZ1kpNySaH
```

Using one unusual path on a Google-owned domain for every action, including the privacy and terms links, is suspicious.

**urlscan.io result.** The scan reported 7 IPs in 3 countries across 7 domains, with 45 HTTP transactions. The main IP was `172[.]66[.]0[.]227` (Cloudflare, US) and the main domain was `x[.]com` (Cisco Umbrella rank 1463). The main domain differs from the host in the email link, which indicates the URL redirects. A high popularity rank does not make the destination safe, so the redirect chain should be treated as unverified until reviewed in full.

## 5. Indicators of compromise

### 5.1 IOC table

| Sample | Sender domain | Sender IP | URLs | Attachment | Hash |
| --- | --- | --- | --- | --- | --- |
| 1 | `kneesway[.]hiddenlakeswinery[.]com` | `74[.]125[.]229[.]4` (shared Google infrastructure) | `hxxps://google[.]com/share[.]google?q=0myWDVBTZ1kpNySaH` | None | N/A |

**Additional identifiers**

| Indicator | Value |
| --- | --- |
| Sender address | `television-uk-mail-supports-3215584@kneesway[.]hiddenlakeswinery[.]com` |
| Reply-To | `noreply@kneesway[.]hiddenlakeswinery[.]com` |
| HELO | `mail-dy2-f4[.]google[.]com` |
| Message-ID domain | `mail[.]gmail[.]com` |
| Reference ID | `TVL34FMMKE0OEYOE1` |
| Subject suffix | `JE2LR` |
| HTML title | `blueberry volaticus tropical` |

The phrase `blueberry volaticus tropical` appears in the HTML title and body. Its purpose is unknown. It may be a template marker, a testing artefact or a campaign identifier.

The same data is available in `ioc-table.csv`.

### 5.2 Reputation checks

| Tool | Indicator | Result |
| --- | --- | --- |
| urlscan.io | Suspicious URL | Scanned, see section 4.4 |
| VirusTotal | Sender domain | Not checked |
| VirusTotal | Suspicious URL | Not checked |

No vendor detection counts or reputation scores are reported because none were obtained. Public scanners make submitted URLs and scan details visible to others, so do not submit links that contain personal tokens.

## 6. Social engineering techniques

| Technique | Evidence | Effect on the recipient |
| --- | --- | --- |
| Urgency and fear | "Third Notice", threat of enforcement action and a £1,000 fine | Pushes quick action instead of verification |
| Authority impersonation | TV Licensing name, official-looking subject line | Makes the message look trustworthy |
| Payment bait | Claims a licence fee is outstanding | Encourages entering payment details |
| Sender mismatch | Brand name on an unrelated domain | Hides the real sender behind a familiar name |
| Filter manipulation | Asks the recipient to move the email out of Junk and add the sender to safe senders | Helps future messages bypass filtering |
| Generic communication | Customer-service identity, recipient in BCC | Consistent with mass phishing rather than targeted spear-phishing |
| Unicode obfuscation | Look-alike and invisible characters | Defeats keyword and text-extraction filters |
| HTML/CSS concealment | Hidden-text styling in the source | May hide content from readers and some filters |

The most effective combination is authority impersonation with urgency and payment pressure: the recipient is led to believe immediate action is needed to avoid a financial or legal consequence.

## 7. Conclusions

The sample is a high-confidence phishing email impersonating TV Licensing, built to collect payment details through threats of enforcement and a fine.

1. The display name claims to be TV Licensing, but the sending domain is unrelated.
2. SPF, DKIM and DMARC all passed for the sending domain, which proves nothing about the claimed brand identity.
3. The subject uses look-alike characters and the body contains invisible Unicode characters.
4. The HTML defines CSS classes associated with hidden content.
5. Every call to action uses the same unusual Google-hosted URL, which redirects elsewhere.
6. The message asks the recipient to move it out of Junk and trust the sender.

**Key lesson:** email investigations should not rely on SPF, DKIM and DMARC alone. Authentication results must be read alongside sender identity, domain reputation, URL behaviour, message content and social engineering cues.

## 8. Limitations and next steps

- **Single sample:** one email cannot show whether these indicators are specific to this message or part of a wider campaign.
- **No VirusTotal results:** the sender domain and URL have not yet been checked. Add verdicts to the table in section 5.2 when available.
- **Redirect chain not fully traced:** the final destination should be confirmed from the full urlscan.io report.
- **Shared infrastructure:** the sending IP belongs to Google and is not a reliable blocking indicator.
- **Possible follow-up:** compare against additional samples to refine the detection rules.
