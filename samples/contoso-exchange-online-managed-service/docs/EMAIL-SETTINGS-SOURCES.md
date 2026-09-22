# Email Settings Sources

ReviewedOn: 2026-09-22

## Scope And Admission

EXR-010-A01 covers the offline, typed email catalogue only: 114 fields, 91 MicrosoftRecommendation fields and 23 LocalPolicy fields, yielding 247 applicable profile-field assertions. MicrosoftRecommendation, LocalPolicy and ApprovedException are distinct: an ApprovedException belongs to independently approved runtime evidence, never a catalogue profile or a fabricated Microsoft label.

Classification and capability are not operational support or mutation support. This document makes no raw getter shape or live compatibility claim. A01 does not complete EXR-010-A02 recipient precedence/effective evaluation or the EXR-010 parent. Supplied capability/recipient entitlement remains externally authoritative under RAID-D02; no licensing is assigned here.

`Get-BaselineEmailSettingCatalog` reads the candidate once. A structured JSON walk rejects duplicate keys, including case collisions, before conversion. Private source-pinned tables in Common independently constrain admitted families, profiles, fields, JSON types, sections, capability and classifications. The candidate and test fixtures do not define their own admission rules. The loader does not download or reread captured source documents for each invocation.

All Standard fields are required. Strict is a sparse overlay: only documented differences are required; any explicit repeated Microsoft value must still match its profile. Local booleans, strings and string arrays remain customizable in each applicable profile, including all 23 fields / 50 explicit entries exercised by the customized catalogue case. No local values are reset to shipped defaults. Empty strings and arrays are valid catalogue choices, not proof that recipient-specific prerequisites are satisfied.

BuiltIn exists only for SafeLinks and SafeAttachment. SafeLinks requires `EnableForInternalSenders=false`, `DisableURLRewrite=true`, and `AllowClickThrough=true`; other values inherit Standard subject to the pinned Built-in column. SafeAttachment has an explicit empty BuiltIn overlay because its eight documented values match Standard, including `Enable=true` and `Action=Block`. It is not the disabled custom-policy default.

`ReviewedOn` must be a real ISO date no earlier than the recommendation's 2026-08-10 document date and no later than today's UTC date. This is dated snapshot admission, not proof of latest or future Microsoft content. A source update requires a new reviewed contract, source bindings, documentation and independent assertions together; changing a URL or date alone cannot update the pinned recommendation values.

## Captured Provenance

The following SHA-256 values identify the actual captured markdown representation. A captured rendered digest is not necessarily the digest of raw immutable-revision bytes. Capture verification on 2026-09-22 matched all ten artifacts from the Silver g13 source evidence directory `cohort-Silver-9bc86259-42e8-4003-b1f0-d3d52835d1bc`; g14 preserved these captures. These captures are review evidence, not runtime dependencies.

| ID | Captured artifact | Recorded revision | SHA-256 | Document date |
| --- | --- | --- | --- | --- |
| R | recommended-current.md | 379db33154f4d944dbb33fce80576aff5296dfbf | 62C0BCA45F818F55D44E1914F7E83B739F67FAF633DD2DCE1A40A0E33E41CF5F | 2026-08-10 |
| RP | recommended-pinned.md | 379db33154f4d944dbb33fce80576aff5296dfbf | 527E7504482B0C8E47DF5030AFD5822B53C20D70223A7EC8DC60CD2123713D31 | 2026-08-10 |
| F | file-types-current.md | a303cf1b405a37ff173ff70117802d92b98ccc05 | 95D86CFB11658B9058F3ADDD54300F33D0764F1FCE4B938A8FA67085792FFCC8 | 2026-06-09 |
| MA | set-malwarefilterpolicy.md | 57263e9e741054c737c2ea5f5a143685dedeef28 | 9079749B43C80190FDF472B0D9F3B08147C85A54C6BE1D7A3407C17D239A5EC7 | 2017-09-25 |
| SP | set-hostedcontentfilterpolicy.md | 5fff4ea010dd9e196e3d82c00184096e868e5ab5 | 38B762D54BC34452D58E231662127E102251650FF3848143925ACD59F9A5CF82 | 2017-09-25 |
| OU | set-hostedoutboundspamfilterpolicy.md | 589c47eee8c4444079d9edb1967f534a950deb08 | 0929B3A4716E60AEDCEE24A70B5AF11111078289B8B19C6AA7E0E3504ADC9DE6 | 2017-09-25 |
| AP | set-antiphishpolicy.md | 0ce92c7b67bb08a4e0ddc014c4cc2ae81f24dcf8 | B2EAF7DEF2CDA86FF88A875A7B591A40DA1F6AF99F60C98507C6650F55FBBF5C | 2017-09-25 |
| SA-N | new-safeattachmentpolicy.md | eda2c42b9b7ab27352dc773176c89e6dee6df78e | 512966D5327D648C3F2C95975EEA7F19B253DD7182688826973045BE54BD950D | 2017-09-25 |
| SA-S | set-safeattachmentpolicy.md | 372c15f972287c9e0d2579f996636ed5ad6951e3 | 4D7E29459193B2DBCEA5B060390BB981097013DA46503AA22C3B8F0E492F7030 | 2017-09-25 |
| SL | set-safelinkspolicy.md | 4d291b907b6a02282e397834a2506e864cfcd7b8 | 0FB296A9B1DC06C3923E30D1DB6EE8C47C904E713AF50D728BEFB62124FB73CB | 2017-09-25 |

R canonical URL: <https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365>. Its captured `gitcommit` identifies <https://github.com/MicrosoftDocs/defender-docs-pr/blob/379db33154f4d944dbb33fce80576aff5296dfbf/defender-office-365/recommended-settings-for-eop-and-office365.md>. RP is the separately captured pinned Markdown for that revision; its digest intentionally differs from R. RP does not itself carry commit metadata; its revision binding is the recorded retrieval, corroborated by R, not an invented embedded property.

F canonical URL: <https://learn.microsoft.com/en-us/defender-office-365/anti-malware-protection-about#common-attachments-filter-in-anti-malware-policies>. Section: Common attachments filter in anti-malware policies, Default file types (53 entries), not the longer true-type-detection list. `FileTypesSourceCommit` is the recorded revision above; `FileTypesSourceSha256` identifies `file-types-current.md`, not a claimed raw revision download. Catalogue URLs retain the equivalent locale-neutral Microsoft Learn forms.

Parameter evidence uses the **Parameters** section of these references; each field below uses its matching parameter heading when present:

| ID | Canonical URL |
| --- | --- |
| MA | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-malwarefilterpolicy?view=exchange-ps> |
| SP | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-hostedcontentfilterpolicy?view=exchange-ps> |
| OU | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-hostedoutboundspamfilterpolicy?view=exchange-ps> |
| AP | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-antiphishpolicy?view=exchange-ps> |
| SA-N | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/new-safeattachmentpolicy?view=exchange-ps> |
| SA-S | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-safeattachmentpolicy?view=exchange-ps> |
| SL | <https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/set-safelinkspolicy?view=exchange-ps> |

## Source Sections And Qualifications

All R section references below use both R and RP above, their bound revision and captured digests. The final column supplies the matching parameter reference ID. Standard and Strict apply to all six families; BuiltIn applies only to the last two.

| Family | Catalogue section | Family capability | Source section links | Parameter evidence |
| --- | --- | --- | --- | --- |
| MalwareFilter | Anti-malware policy settings | Exchange | [R: anti-malware](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-malware-policy-settings); F for FileTypes | MA |
| HostedContentFilter | Anti-spam policy settings / ASF settings in anti-spam policies | Exchange | [R: anti-spam](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-spam-policy-settings); [R: ASF](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#asf-settings-in-anti-spam-policies) | SP |
| HostedOutboundSpamFilter | Outbound spam policy settings | Exchange | [R: outbound](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#outbound-spam-policy-settings) | OU |
| AntiPhish | Anti-phishing policy settings for all cloud mailboxes / Impersonation settings / Phishing email thresholds | ExchangeAndDefender | [R: spoof](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#anti-phishing-policy-settings-for-all-cloud-mailboxes); [R: impersonation](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#impersonation-settings-in-anti-phishing-policies-in-microsoft-defender-for-office-365); [R: thresholds](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#phishing-email-thresholds-in-anti-phishing-policies-in-microsoft-defender-for-office-365) | AP |
| SafeAttachment | Safe Attachments policy settings | Defender | [R: attachments](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#safe-attachments-policy-settings) | SA-N, SA-S; uncertainty below |
| SafeLinks | Safe Links policy settings (Email and Click protection only) | Defender | [R: links](https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365#safe-links-policy-settings), Email, Click protection and Notification only | SL |

HostedOutboundSpamFilter / outbound spam recommendations are outside Standard and Strict presets; their profile names identify recommended values for default/custom outbound policies, not preset membership.

`BccSuspiciousOutboundMail` and `BccSuspiciousOutboundAdditionalRecipients` are default-policy-only. They do not operate in custom outbound policies. The R Outbound spam policy settings section and OU Parameters reference must be read with that qualification.

The encrypted-attachment recommendations are conditional, not universal operational defaults. `EnableBlockingEncryptedAttachments` is available only with `Enable=true` and `Action=Block`. `ExcludedTypesFromBlockingEncryptedAttachments` and `QuarantineTagForBlockingEncryptedAttachments` apply to the blocking path when `EnableBlockingEncryptedAttachments=true`; the quarantine tag concerns messages quarantined for unscannable encrypted attachments. The snapshot recommends the blocking switch false, not mandatory encrypted-attachment blocking.

`EnableBlockingEncryptedAttachments` appears in the R recommendation table but is absent from the captured New-SafeAttachmentPolicy and Set-SafeAttachmentPolicy Parameters references; operational support is uncertain.

`ExcludedTypesFromBlockingEncryptedAttachments` appears in the R recommendation table but is absent from the captured New-SafeAttachmentPolicy and Set-SafeAttachmentPolicy Parameters references; operational support is uncertain.

`QuarantineTagForBlockingEncryptedAttachments` appears in the R recommendation table but is absent from the captured New-SafeAttachmentPolicy and Set-SafeAttachmentPolicy Parameters references; operational support is uncertain.

No supported mutation is established by those table entries. Do not infer callable parameters, raw collection properties, or successful deployment from catalogue admission. No live cmdlet probing or mutation was performed. The recommendation article's Safe Attachments paragraph also links its Set-SafeAttachmentPolicy label to a Safe Links URL; SA-S above is the correctly named independently captured reference.

Quarantine tags are verdict/action-dependent. DMARC actions depend on HonorDmarcPolicy; impersonation targets remain locally selected, and exclusion lists require separate approval. R notes government-cloud differences for IntraOrgFilterState=Default and the BulkMovesEnabled preview status. None of those qualifications is a claim of service availability or recipient-effective protection.

## Field Map

Every row supplies the JSON type, classification, capability and source subsection. `R/ASF`, `R/spoof`, `R/impersonation` and `R/thresholds` select the subsection links above; other R rows use the family's section. Each row also inherits the family's parameter evidence ID above. An array means JSON array with string members. LocalPolicy indicates an organization-owned choice, not a normative fixed Microsoft value, even where the source displays a default.

| Family | Field | JSON type | Classification | Capability | Recommendation section |
| --- | --- | --- | --- | --- | --- |
| MalwareFilter | EnableFileFilter | Boolean | MicrosoftRecommendation | Exchange | R |
| MalwareFilter | FileTypeAction | String | MicrosoftRecommendation | Exchange | R |
| MalwareFilter | ZapEnabled | Boolean | MicrosoftRecommendation | Exchange | R |
| MalwareFilter | QuarantineTag | String | MicrosoftRecommendation | Exchange | R |
| MalwareFilter | FileTypes | Array | MicrosoftRecommendation | Exchange | F |
| MalwareFilter | EnableInternalSenderAdminNotifications | Boolean | LocalPolicy | Exchange | R |
| MalwareFilter | InternalSenderAdminAddress | String | LocalPolicy | Exchange | R |
| MalwareFilter | EnableExternalSenderAdminNotifications | Boolean | LocalPolicy | Exchange | R |
| MalwareFilter | ExternalSenderAdminAddress | String | LocalPolicy | Exchange | R |
| MalwareFilter | CustomNotifications | Boolean | LocalPolicy | Exchange | R |
| MalwareFilter | CustomFromName | String | LocalPolicy | Exchange | R |
| MalwareFilter | CustomFromAddress | String | LocalPolicy | Exchange | R |
| MalwareFilter | CustomInternalSubject | String | LocalPolicy | Exchange | R |
| MalwareFilter | CustomInternalBody | String | LocalPolicy | Exchange | R |
| MalwareFilter | CustomExternalSubject | String | LocalPolicy | Exchange | R |
| MalwareFilter | CustomExternalBody | String | LocalPolicy | Exchange | R |
| HostedContentFilter | BulkThreshold | Integer | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | MarkAsSpamBulkMail | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | EnableLanguageBlockList | Boolean | LocalPolicy | Exchange | R |
| HostedContentFilter | LanguageBlockList | Array | LocalPolicy | Exchange | R |
| HostedContentFilter | EnableRegionBlockList | Boolean | LocalPolicy | Exchange | R |
| HostedContentFilter | RegionBlockList | Array | LocalPolicy | Exchange | R |
| HostedContentFilter | SpamAction | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | SpamQuarantineTag | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | HighConfidenceSpamAction | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | HighConfidenceSpamQuarantineTag | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | PhishSpamAction | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | PhishQuarantineTag | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | HighConfidencePhishAction | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | HighConfidencePhishQuarantineTag | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | BulkSpamAction | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | BulkQuarantineTag | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | BulkMovesEnabled | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | IntraOrgFilterState | String | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | QuarantineRetentionPeriod | Integer | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | InlineSafetyTipsEnabled | Boolean | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | PhishZapEnabled | Boolean | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | SpamZapEnabled | Boolean | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | AllowedSenders | Array | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | AllowedSenderDomains | Array | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | BlockedSenders | Array | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | BlockedSenderDomains | Array | MicrosoftRecommendation | Exchange | R |
| HostedContentFilter | TestModeAction | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | IncreaseScoreWithImageLinks | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | IncreaseScoreWithNumericIps | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | IncreaseScoreWithRedirectToOtherPort | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | IncreaseScoreWithBizOrInfoUrls | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamEmptyMessages | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamEmbedTagsInHtml | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamJavaScriptInHtml | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamFormTagsInHtml | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamFramesInHtml | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamWebBugsInHtml | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamObjectTagsInHtml | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamSensitiveWordList | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamSpfRecordHardFail | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamFromAddressAuthFail | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedContentFilter | MarkAsSpamNdrBackscatter | String | MicrosoftRecommendation | Exchange | R/ASF |
| HostedOutboundSpamFilter | RecipientLimitExternalPerHour | Integer | MicrosoftRecommendation | Exchange | R |
| HostedOutboundSpamFilter | RecipientLimitInternalPerHour | Integer | MicrosoftRecommendation | Exchange | R |
| HostedOutboundSpamFilter | RecipientLimitPerDay | Integer | MicrosoftRecommendation | Exchange | R |
| HostedOutboundSpamFilter | ActionWhenThresholdReached | String | MicrosoftRecommendation | Exchange | R |
| HostedOutboundSpamFilter | AutoForwardingMode | String | MicrosoftRecommendation | Exchange | R |
| HostedOutboundSpamFilter | BccSuspiciousOutboundMail | Boolean | MicrosoftRecommendation | Exchange | R; default-policy-only |
| HostedOutboundSpamFilter | BccSuspiciousOutboundAdditionalRecipients | Array | MicrosoftRecommendation | Exchange | R; default-policy-only |
| HostedOutboundSpamFilter | NotifyOutboundSpam | Boolean | MicrosoftRecommendation | Exchange | R |
| HostedOutboundSpamFilter | NotifyOutboundSpamRecipients | Array | MicrosoftRecommendation | Exchange | R |
| AntiPhish | EnableSpoofIntelligence | Boolean | MicrosoftRecommendation | Exchange | R/spoof |
| AntiPhish | HonorDmarcPolicy | Boolean | MicrosoftRecommendation | Exchange | R/spoof |
| AntiPhish | DmarcQuarantineAction | String | MicrosoftRecommendation | Exchange | R/spoof |
| AntiPhish | DmarcRejectAction | String | MicrosoftRecommendation | Exchange | R/spoof |
| AntiPhish | AuthenticationFailAction | String | MicrosoftRecommendation | Exchange | R/spoof |
| AntiPhish | SpoofQuarantineTag | String | MicrosoftRecommendation | Exchange | R/spoof |
| AntiPhish | EnableFirstContactSafetyTips | Boolean | MicrosoftRecommendation | Exchange | R/spoof |
| AntiPhish | EnableUnauthenticatedSender | Boolean | MicrosoftRecommendation | Exchange | R/spoof |
| AntiPhish | EnableViaTag | Boolean | MicrosoftRecommendation | Exchange | R/spoof |
| AntiPhish | PhishThresholdLevel | Integer | MicrosoftRecommendation | Defender | R/thresholds |
| AntiPhish | EnableTargetedUserProtection | Boolean | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | EnableOrganizationDomainsProtection | Boolean | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | EnableTargetedDomainsProtection | Boolean | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | TargetedUsersToProtect | Array | LocalPolicy | Defender | R/impersonation |
| AntiPhish | TargetedDomainsToProtect | Array | LocalPolicy | Defender | R/impersonation |
| AntiPhish | ExcludedSenders | Array | LocalPolicy | Defender | R/impersonation |
| AntiPhish | ExcludedDomains | Array | LocalPolicy | Defender | R/impersonation |
| AntiPhish | EnableMailboxIntelligence | Boolean | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | EnableMailboxIntelligenceProtection | Boolean | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | TargetedUserProtectionAction | String | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | TargetedDomainProtectionAction | String | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | TargetedUserQuarantineTag | String | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | TargetedDomainQuarantineTag | String | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | MailboxIntelligenceProtectionAction | String | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | MailboxIntelligenceQuarantineTag | String | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | EnableSimilarUsersSafetyTips | Boolean | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | EnableSimilarDomainsSafetyTips | Boolean | MicrosoftRecommendation | Defender | R/impersonation |
| AntiPhish | EnableUnusualCharactersSafetyTips | Boolean | MicrosoftRecommendation | Defender | R/impersonation |
| SafeAttachment | Enable | Boolean | MicrosoftRecommendation | Defender | R |
| SafeAttachment | Action | String | MicrosoftRecommendation | Defender | R |
| SafeAttachment | QuarantineTag | String | MicrosoftRecommendation | Defender | R |
| SafeAttachment | Redirect | Boolean | MicrosoftRecommendation | Defender | R |
| SafeAttachment | RedirectAddress | String | MicrosoftRecommendation | Defender | R |
| SafeAttachment | EnableBlockingEncryptedAttachments | Boolean | MicrosoftRecommendation | Defender | R; conditional, cmdlet support uncertain |
| SafeAttachment | ExcludedTypesFromBlockingEncryptedAttachments | Array | MicrosoftRecommendation | Defender | R; conditional, cmdlet support uncertain |
| SafeAttachment | QuarantineTagForBlockingEncryptedAttachments | String | MicrosoftRecommendation | Defender | R; conditional, cmdlet support uncertain |
| SafeLinks | EnableSafeLinksForEmail | Boolean | MicrosoftRecommendation | Defender | R/Email |
| SafeLinks | EnableForInternalSenders | Boolean | MicrosoftRecommendation | Defender | R/Email |
| SafeLinks | ScanUrls | Boolean | MicrosoftRecommendation | Defender | R/Email |
| SafeLinks | DeliverMessageAfterScan | Boolean | MicrosoftRecommendation | Defender | R/Email |
| SafeLinks | DisableURLRewrite | Boolean | MicrosoftRecommendation | Defender | R/Email |
| SafeLinks | DoNotRewriteUrls | Array | LocalPolicy | Defender | R/Email |
| SafeLinks | TrackClicks | Boolean | MicrosoftRecommendation | Defender | R/Click protection |
| SafeLinks | AllowClickThrough | Boolean | MicrosoftRecommendation | Defender | R/Click protection |
| SafeLinks | EnableOrganizationBranding | Boolean | LocalPolicy | Defender | R/Click protection |
| SafeLinks | CustomNotificationText | String | LocalPolicy | Defender | R/Notification |
| SafeLinks | UseTranslatedNotificationText | Boolean | LocalPolicy | Defender | R/Notification |

The excluded workload set is `EnableATPForSPOTeamsODB`, `EnableSafeDocs`, `AllowSafeDocsOpen`, `EnableSafeLinksForTeams`, `EnableSafeLinksForOffice`, and `TeamsProtectionPolicy`. These are neither admitted fields nor new families. Their exclusion does not attest external workload protection.

## Control And Evidence Mapping

Recommendation source S14 / assessment A08 in [the recommendation inventory](../config/exchange-recommendations.v1.json) maps this catalogue to MDO-001, MDO-002, MDO-003, MDO-008 and MDO-009; outbound forwarding also informs EXO-004. The [control catalogue](CONTROL-CATALOG.md#email-catalogue-boundary) and [ExchangeOnly procedure](EXCHANGE-ONLY.md#email-catalogue-review) distinguish offline catalogue acceptance from effective recipient evidence. No new control, evidence result, public command or mutation surface is introduced.

`ExchangeEmailSettingCatalog.Tests.ps1` covers admission/source evidence and the single positive unit with shipped and independently customized candidates. `ExchangeProtectionMatrix.Tests.ps1` retains its separate field drift/missing regressions. Those checks do not close A02, certify raw getters, authorize changes or certify a real tenant. Parent coverage remains Partial pending its other accepted children.
