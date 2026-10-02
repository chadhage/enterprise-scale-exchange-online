'use strict';

const menuToggle = document.getElementById('menuToggle');
const navigationDrawer = document.getElementById('navigationDrawer');
const drawerClose = document.getElementById('drawerClose');
const drawerBackdrop = document.getElementById('drawerBackdrop');
const navItems = document.querySelectorAll('.nav-item');
const copyCloneUrl = document.getElementById('copyCloneUrl');
const copyStatus = document.getElementById('copyStatus');
const sectionLinks = document.querySelectorAll('[data-section-link]');
const documentCatalog = [
    'APPROVED-CHANGE.md',
    'CONTROL-CATALOG.md',
    'DESIGN.md',
    'EMAIL-SETTINGS-SOURCES.md',
    'EXCHANGE-ADMINISTRATOR-JOURNEY.md',
    'EXCHANGE-EMAIL-PROTECTION.md',
    'EXCHANGE-GO-LIVE.md',
    'EXCHANGE-GOVERNANCE.md',
    'EXCHANGE-ONLY.md',
    'EXR005-ADAPTER-AUDIT.md',
    'EXR007-RECOMMENDATION-INVENTORY.md',
    'IMPLEMENTATION-GUIDE.md',
    'LICENSING-GATE.md',
    'RUNBOOKS.md'
];
let changeWizard = null;
let lastFocusedElement = null;
let previousSection = 'resources';
let activeDocument = '';

function slugifyHeading(text) {
    return text
        .toLowerCase()
        .replace(/<[^>]*>/g, '')
        .replace(/[`*_~]/g, '')
        .replace(/[^a-z0-9\s-]/g, '')
        .trim()
        .replace(/\s+/g, '-');
}

function getRepositoryDocumentUrl(fileName) {
    return `https://github.com/chadhage/enterprise-scale-exchange-online/blob/main/samples/contoso-exchange-online-managed-service/docs/${encodeURIComponent(fileName)}`;
}

function makeDocumentationLink(label, target, sourceFile) {
    const link = document.createElement('a');
    link.textContent = label;
    const trimmedTarget = target.trim();
    if (trimmedTarget.startsWith('#')) {
        const section = trimmedTarget.slice(1);
        link.href = `#doc=${encodeURIComponent(sourceFile)}&section=${encodeURIComponent(section)}`;
        link.dataset.document = sourceFile;
        link.dataset.documentSection = section;
        return link;
    }

    let resolvedUrl;
    try {
        resolvedUrl = new URL(trimmedTarget, getRepositoryDocumentUrl(sourceFile));
    } catch {
        return document.createTextNode(label);
    }

    if (!['https:', 'http:', 'mailto:'].includes(resolvedUrl.protocol)) {
        return document.createTextNode(label);
    }

    if (resolvedUrl.hostname === 'github.com' && resolvedUrl.pathname.includes('/docs/')) {
        const documentName = decodeURIComponent(resolvedUrl.pathname.split('/').pop());
        if (documentCatalog.includes(documentName)) {
            link.href = `#doc=${encodeURIComponent(documentName)}${resolvedUrl.hash ? `&section=${encodeURIComponent(resolvedUrl.hash.slice(1))}` : ''}`;
            link.dataset.document = documentName;
            if (resolvedUrl.hash) {
                link.dataset.documentSection = resolvedUrl.hash.slice(1);
            }
            return link;
        }
    }

    link.href = resolvedUrl.href;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    return link;
}

function appendInlineMarkdown(parent, source, sourceFile) {
    const pattern = /(`[^`]+`|\[[^\]]+\]\([^)]+\)|\*\*.+?\*\*|~~.+?~~|\*.+?\*)/g;
    let lastIndex = 0;
    let match;
    while ((match = pattern.exec(source)) !== null) {
        parent.append(document.createTextNode(source.slice(lastIndex, match.index)));
        const token = match[0];
        if (token.startsWith('`')) {
            const code = document.createElement('code');
            code.textContent = token.slice(1, -1);
            parent.append(code);
        } else if (token.startsWith('[')) {
            const linkMatch = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(token);
            if (linkMatch) {
                parent.append(makeDocumentationLink(linkMatch[1], linkMatch[2], sourceFile));
            } else {
                parent.append(document.createTextNode(token));
            }
        } else {
            const elementName = token.startsWith('**') ? 'strong' : token.startsWith('~~') ? 'del' : 'em';
            const markerLength = token.startsWith('**') || token.startsWith('~~') ? 2 : 1;
            const element = document.createElement(elementName);
            appendInlineMarkdown(element, token.slice(markerLength, -markerLength), sourceFile);
            parent.append(element);
        }
        lastIndex = pattern.lastIndex;
    }
    parent.append(document.createTextNode(source.slice(lastIndex)));
}

function appendTableRow(row, values, sourceFile, header = false) {
    const tableRow = document.createElement('tr');
    values.forEach(value => {
        const cell = document.createElement(header ? 'th' : 'td');
        appendInlineMarkdown(cell, value.trim(), sourceFile);
        tableRow.append(cell);
    });
    row.append(tableRow);
}

function renderMarkdown(markdown, sourceFile) {
    const content = document.createDocumentFragment();
    const headings = [];
    const lines = markdown
        .replace(/\r\n?/g, '\n')
        .replace(/<!--[\s\S]*?-->/g, '')
        .split('\n');
    let index = 0;

    while (index < lines.length) {
        const line = lines[index];
        if (!line.trim()) {
            index += 1;
            continue;
        }

        const fence = /^\s*```([A-Za-z0-9_-]*)\s*$/.exec(line);
        if (fence) {
            const codeLines = [];
            index += 1;
            while (index < lines.length && !/^\s*```\s*$/.test(lines[index])) {
                codeLines.push(lines[index]);
                index += 1;
            }
            index += 1;
            const pre = document.createElement('pre');
            const code = document.createElement('code');
            code.textContent = codeLines.join('\n');
            if (fence[1]) {
                code.dataset.language = fence[1];
            }
            pre.append(code);
            content.append(pre);
            continue;
        }

        const heading = /^(#{1,6})\s+(.+?)\s*#*\s*$/.exec(line);
        if (heading) {
            const level = heading[1].length;
            const title = heading[2];
            const element = document.createElement(`h${level}`);
            element.id = slugifyHeading(title);
            appendInlineMarkdown(element, title, sourceFile);
            content.append(element);
            if (level === 2 || level === 3) {
                headings.push({ id: element.id, level, title });
            }
            index += 1;
            continue;
        }

        if (/^\s*\|/.test(line) && index + 1 < lines.length && /^\s*\|?[\s:|-]+\|?\s*$/.test(lines[index + 1])) {
            const table = document.createElement('table');
            const head = document.createElement('thead');
            const body = document.createElement('tbody');
            const headerValues = line.trim().replace(/^\||\|$/g, '').split('|');
            appendTableRow(head, headerValues, sourceFile, true);
            index += 2;
            while (index < lines.length && /^\s*\|/.test(lines[index])) {
                appendTableRow(body, lines[index].trim().replace(/^\||\|$/g, '').split('|'), sourceFile);
                index += 1;
            }
            table.append(head, body);
            content.append(table);
            continue;
        }

        if (/^\s*([-*_])(?:\s*\1){2,}\s*$/.test(line)) {
            content.append(document.createElement('hr'));
            index += 1;
            continue;
        }

        const listItem = /^\s*(?:([-+*])|(\d+)\.)\s+(.+)$/.exec(line);
        if (listItem) {
            const list = document.createElement(listItem[2] ? 'ol' : 'ul');
            const ordered = Boolean(listItem[2]);
            while (index < lines.length) {
                const item = /^\s*(?:([-+*])|(\d+)\.)\s+(.+)$/.exec(lines[index]);
                if (!item || Boolean(item[2]) !== ordered) {
                    break;
                }
                const li = document.createElement('li');
                appendInlineMarkdown(li, item[3], sourceFile);
                list.append(li);
                index += 1;
            }
            content.append(list);
            continue;
        }

        if (/^\s*>/.test(line)) {
            const quote = document.createElement('blockquote');
            while (index < lines.length && /^\s*>/.test(lines[index])) {
                const paragraph = document.createElement('p');
                appendInlineMarkdown(paragraph, lines[index].replace(/^\s*>\s?/, ''), sourceFile);
                quote.append(paragraph);
                index += 1;
            }
            content.append(quote);
            continue;
        }

        if (/^\s*</.test(line)) {
            index += 1;
            continue;
        }

        const paragraphText = [line.trim()];
        index += 1;
        while (index < lines.length && lines[index].trim() &&
            !/^(#{1,6})\s/.test(lines[index]) &&
            !/^\s*```/.test(lines[index]) &&
            !/^\s*(?:[-+*]|\d+\.)\s+/.test(lines[index]) &&
            !/^\s*\|/.test(lines[index]) &&
            !/^\s*>/.test(lines[index])) {
            paragraphText.push(lines[index].trim());
            index += 1;
        }
        const paragraph = document.createElement('p');
        appendInlineMarkdown(paragraph, paragraphText.join(' '), sourceFile);
        content.append(paragraph);
    }

    return { content, headings };
}

function buildDocumentContents(headings) {
    const contents = document.getElementById('documentContents');
    contents.replaceChildren();
    headings.forEach(heading => {
        const item = document.createElement('li');
        item.classList.toggle('is-subheading', heading.level === 3);
        const link = document.createElement('a');
        link.href = `#${heading.id}`;
        link.textContent = heading.title;
        link.addEventListener('click', event => {
            event.preventDefault();
            document.getElementById(heading.id)?.scrollIntoView({ behavior: 'smooth' });
            history.replaceState(null, '', `#doc=${encodeURIComponent(activeDocument)}&section=${encodeURIComponent(heading.id)}`);
        });
        item.append(link);
        contents.append(item);
    });
}

async function openDocumentation(fileName, section = '') {
    if (!documentCatalog.includes(fileName)) {
        return;
    }
    const viewer = document.getElementById('documentViewer');
    const title = document.getElementById('documentTitle');
    const status = document.getElementById('documentStatus');
    const content = document.getElementById('documentContent');
    const sourceLink = document.getElementById('documentSourceLink');

    if (!viewer.classList.contains('active')) {
        const active = document.querySelector('.section.active');
        previousSection = active && active.id !== 'documentViewer' ? active.id : 'resources';
    }
    activeDocument = fileName;
    document.querySelectorAll('.section').forEach(item => item.classList.remove('active'));
    viewer.classList.add('active');
    navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.section === 'resources');
        item.setAttribute('aria-current', item.dataset.section === 'resources' ? 'page' : 'false');
    });

    title.textContent = fileName.replace(/\.md$/i, '').replace(/-/g, ' ');
    status.textContent = 'Loading repository guide…';
    content.replaceChildren();
    sourceLink.href = getRepositoryDocumentUrl(fileName);
    closeDrawer();
    window.scrollTo(0, 0);

    try {
        const response = await fetch(`docs/${encodeURIComponent(fileName)}`);
        if (!response.ok) {
            throw new Error(`The published documentation file returned ${response.status}.`);
        }
        const markdown = await response.text();
        const rendered = renderMarkdown(markdown, fileName);
        content.replaceChildren(rendered.content);
        const heading = content.querySelector('h1');
        if (heading) {
            title.textContent = heading.textContent;
            heading.remove();
        }
        buildDocumentContents(rendered.headings);
        addCopyButtons(content);
        markExternalLinks(content);
        status.textContent = 'Repository documentation, rendered within the microsite.';
        if (section) {
            requestAnimationFrame(() => {
                const target = Array.from(content.querySelectorAll('[id]')).find(element => element.id === section);
                target?.scrollIntoView();
            });
        } else {
            window.scrollTo(0, 0);
        }
        title.focus({ preventScroll: true });
    } catch (error) {
        status.textContent = window.location.protocol === 'file:'
            ? 'Browsers block rendered guides on file:// pages. Run ./microsite/Start-MicrositePreview.ps1 -Open from the repository root, or use the source link.'
            : `Unable to load this guide: ${error.message}`;
        content.replaceChildren();
    }
}

function markExternalLinks(root) {
    root.querySelectorAll('a[target="_blank"]').forEach(link => {
        if (link.querySelector('.visually-hidden')) {
            return;
        }
        const hint = document.createElement('span');
        hint.className = 'visually-hidden';
        hint.textContent = ' (opens in a new tab)';
        link.append(hint);
        if (!link.title) {
            link.title = `Opens ${link.hostname || 'an external site'} in a new tab`;
        }
    });
}

function addCopyButtons(root) {
    root.querySelectorAll('pre').forEach(pre => {
        const code = pre.querySelector('code');
        if (!code || pre.closest('.terminal-sample') || pre.parentElement.classList.contains('copyable-code')) {
            return;
        }
        const wrapper = document.createElement('div');
        wrapper.className = 'copyable-code';
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'code-copy';
        button.textContent = 'Copy';
        button.setAttribute('aria-label', 'Copy command to clipboard');
        button.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(code.textContent);
                button.textContent = 'Copied';
            } catch {
                button.textContent = 'Select to copy';
            }
            setTimeout(() => { button.textContent = 'Copy'; }, 2000);
        });
        pre.replaceWith(wrapper);
        wrapper.append(button, pre);
    });
}

const viewStateKey = 'exchangeMicrositeView';

function readViewState() {
    try {
        return JSON.parse(sessionStorage.getItem(viewStateKey)) || {};
    } catch {
        return {};
    }
}

function saveViewState(changes) {
    try {
        sessionStorage.setItem(viewStateKey, JSON.stringify({ ...readViewState(), ...changes }));
    } catch {
        // Storage can be unavailable (private mode, file://); refresh then simply starts at the overview.
    }
}

function routeHash() {
    const parameters = new URLSearchParams(window.location.hash.slice(1));
    const fileName = parameters.get('doc');
    if (fileName) {
        openDocumentation(fileName, parameters.get('section') || '');
    } else if (document.getElementById('documentViewer').classList.contains('active')) {
        showSection(previousSection, document.querySelector(`.nav-item[data-section="${previousSection}"]`));
    }
}

const scopeCatalog = [
    { area: 'Mail flow and organization', id: 'Transport', text: 'Tenant transport settings, such as turning off SMTP AUTH.' },
    { area: 'Mail flow and organization', id: 'Organization', text: 'Organization-wide settings, such as auditing and legacy EWS access.' },
    { area: 'Mail flow and organization', id: 'AcceptedDomains', text: 'Accepted domain settings for your verified domains.' },
    { area: 'Mail flow and organization', id: 'RemoteDomains', text: 'Automatic replies and forwarding to external domains.' },
    { area: 'Mail flow and organization', id: 'ExternalSender', text: 'The External tag Outlook shows on outside mail.' },
    { area: 'Mail flow and organization', id: 'OutboundSpam', text: 'Outbound spam limits and automatic external forwarding.', options: ['outboundSpam'] },
    { area: 'Mail flow and organization', id: 'Forwarding', text: 'Blocks inbox rules that forward mail outside the organization.' },
    { area: 'Mail flow and organization', id: 'Dkim', text: 'DKIM signing for your domains.', options: ['enableDkim'] },
    { area: 'Mail flow and organization', id: 'TransportBypass', text: 'Governed spam-filter bypass for authenticated partner mail.', required: ['transportSclExceptions'], options: ['externalSubjectPrefixRules'] },
    { area: 'Mail flow and organization', id: 'ConnectorTrust', text: 'Inbound and outbound connectors with verified TLS.', required: ['connectorTrust'] },
    { area: 'Client access', id: 'MailboxProtocols', text: 'Turns off legacy protocols (POP, IMAP) on existing mailboxes.' },
    { area: 'Client access', id: 'MailboxPlans', text: 'Turns off legacy protocols for new mailboxes.' },
    { area: 'Client access', id: 'AddInAcquisition', text: 'Who can install Outlook add-ins.' },
    { area: 'Threat protection', id: 'EopPresets', text: 'Assigns the Standard and Strict Exchange Online Protection presets.', presets: true },
    { area: 'Threat protection', id: 'AtpPresets', text: 'Assigns the Standard and Strict Defender for Office 365 presets.', presets: true, atp: true },
    { area: 'Threat protection', id: 'BuiltInProtection', text: 'Defender built-in protection (Safe Links and Safe Attachments).', atp: true },
    { area: 'Threat protection', id: 'Impersonation', text: 'Protects named users and domains from impersonation.', atp: true },
    { area: 'Threat protection', id: 'Quarantine', text: 'Quarantine policies and notifications.' },
    { area: 'Threat protection', id: 'SecOpsOverride', text: 'Registers the SecOps mailbox so phishing samples reach it.' },
    { area: 'Threat protection', id: 'ReportSubmission', text: 'Where user-reported messages go.' },
    { area: 'Threat protection', id: 'TenantAllowBlockList', text: 'Governed allow and block entries that expire.', options: ['tenantAllowBlockEntries'] },
    { area: 'Threat protection', id: 'OrganizationAllowList', text: 'Governed IP, sender, and domain allow entries.', required: ['organizationAllowList'] },
    { area: 'Mailbox access', id: 'FullAccess', text: 'Grants or removes full mailbox access.', required: ['fullAccessDelegations'] },
    { area: 'Mailbox access', id: 'SendAs', text: 'Grants or removes Send As.', required: ['sendAsDelegations'] },
    { area: 'Mailbox access', id: 'SendOnBehalf', text: 'Grants or removes Send on Behalf.', required: ['sendOnBehalfDelegations'] },
    { area: 'Mailbox access', id: 'MailboxSafeSender', text: 'Safe senders on specific mailboxes.', required: ['mailboxSafeSenders'] },
    { area: 'Sharing and partners', id: 'SharingPolicyBinding', text: 'Calendar sharing policies and who uses them.', required: ['sharingPolicyBinding'] },
    { area: 'Sharing and partners', id: 'OrganizationRelationship', text: 'Free/busy sharing with a partner organization.', required: ['organizationRelationships'] },
    { area: 'Applications', id: 'ApplicationAssignmentScope', text: 'Limits which mailboxes an app can access.', required: ['applicationAssignmentScope'] },
    { area: 'Governance', id: 'GovernanceMailboxPolicy', text: 'Mailbox governance policy settings.', governance: true },
    { area: 'Governance', id: 'GovernanceMrm', text: 'Messaging records management (retention) policy.', governance: true },
    { area: 'Governance', id: 'GovernanceEncryption', text: 'Message encryption (IRM) configuration.', governance: true }
];

const approvalTemplate = { owner: 'REPLACE-owner@contoso.com', approval: 'REPLACE-CHG-1001', expiresOn: 'REPLACE-2026-12-31T00:00:00Z' };

const optionCatalog = {
    enableDkim: { title: 'Turn on DKIM signing', how: 'Publish both DKIM CNAME records in DNS first, then set this to true.', value: true },
    outboundSpam: {
        title: 'Custom outbound spam policy (otherwise the default policy turns external auto-forwarding off)',
        how: 'Name the policy and rule, list who it applies to, and set the limits your ticket approves.',
        value: {
            policyIdentity: 'REPLACE-Outbound policy name', ruleIdentity: 'REPLACE-Outbound rule name', profile: 'Strict',
            settings: {
                RecipientLimitExternalPerHour: 400, RecipientLimitInternalPerHour: 800, RecipientLimitPerDay: 800,
                ActionWhenThresholdReached: 'BlockUser', AutoForwardingMode: 'Off',
                BccSuspiciousOutboundMail: false, BccSuspiciousOutboundAdditionalRecipients: [],
                NotifyOutboundSpam: true, NotifyOutboundSpamRecipients: ['REPLACE-secops@contoso.com']
            },
            senderScope: { From: [], FromMemberOf: ['REPLACE-group@contoso.com'], SenderDomainIs: [], ExceptIfFrom: [], ExceptIfFromMemberOf: [], ExceptIfSenderDomainIs: [] }
        }
    },
    tenantAllowBlockEntries: {
        title: 'Allow or block entries',
        how: 'One entry per sender, domain, URL, or file hash. Allows last at most 30 days; blocks last exactly 90 days.',
        value: [{
            entryType: 'Sender', entryValue: 'REPLACE-sender@fabrikam.com', action: 'Block', owner: 'REPLACE-owner@contoso.com',
            ticket: 'REPLACE-CHG-1001', createdDateTime: 'REPLACE-2026-10-01T00:00:00Z', expirationDateTime: 'REPLACE-2026-12-30T00:00:00Z',
            justification: 'REPLACE-Why this entry is needed'
        }]
    },
    externalSubjectPrefixRules: {
        title: 'Remove an old [External] subject-prefix rule',
        how: 'Name the existing transport rule that adds the prefix; it is removed because Outlook now shows the External tag.',
        value: [{ identity: 'REPLACE-Existing transport rule name', prefix: '[External]', action: 'Remove' }]
    },
    transportSclExceptions: {
        title: 'Spam-filter bypass for an authenticated partner',
        how: 'Partner domains and sending IP ranges (IPv4 /24 or narrower, IPv6 /64 or narrower). The bypass only applies when SPF, DKIM, and DMARC pass.',
        value: [{
            identity: 'REPLACE-Partner bypass rule', senderDomains: ['REPLACE-partner.com'], senderIpRanges: ['REPLACE-203.0.113.0/24'],
            authentication: { header: 'Authentication-Results', requiredResults: ['spf=pass', 'dkim=pass', 'dmarc=pass'] }, setScl: -1, ...approvalTemplate
        }]
    },
    connectorTrust: {
        title: 'Connectors',
        how: 'Describe each connector exactly as your network owner approved it, including TLS evidence. No new infrastructure is created.',
        value: {
            inbound: [], outbound: [], externalRoutingHandoffs: [], provisionExternalInfrastructure: false,
            desired: {
                inbound: { identity: 'REPLACE-Inbound connector', enabled: true, senderDomains: ['REPLACE-partner.com'], senderIPAddresses: [], tlsSenderCertificateName: 'REPLACE-mail.partner.com', restrictDomainsToCertificate: true, restrictDomainsToIPAddresses: false, requireTls: true },
                outbound: { identity: 'REPLACE-Outbound connector', enabled: true, recipientDomains: ['REPLACE-partner.com'], smartHosts: ['REPLACE-smtp.partner.com'], tlsSettings: 'DomainValidation', tlsDomain: 'REPLACE-smtp.partner.com', routeAllMessagesViaOnPremises: false, useMxRecord: false }
            }
        }
    },
    organizationAllowList: {
        title: 'Organization allow list',
        how: 'Each IP (/32 or /128), sender, or domain needs an owner, approval, expiry, and verified authentication evidence.',
        value: {
            connectionFilter: { identity: 'Default', ipAllowEntries: [], enableSafeList: false },
            antiSpam: { identity: 'Default', allowedSenders: [{ kind: 'Sender', value: 'REPLACE-sender@partner.com', ...approvalTemplate }], allowedSenderDomains: [] }
        }
    },
    fullAccessDelegations: {
        title: 'Full Access grants',
        how: 'One entry per mailbox and delegate, with identity and ownership evidence from your identity owner.',
        value: [{
            mailbox: 'REPLACE-shared@contoso.com', mailboxType: 'SharedMailbox', delegate: 'REPLACE-user@contoso.com', delegateType: 'User', ...approvalTemplate,
            identityEvidence: { resolved: true, source: 'REPLACE-Entra ID', reference: 'REPLACE-evidence reference' },
            ownershipEvidence: { resolved: true, source: 'REPLACE-Mailbox owner', reference: 'REPLACE-evidence reference' }
        }]
    },
    sendAsDelegations: {
        title: 'Send As grants',
        how: 'One entry per recipient and trustee, with identity and ownership evidence.',
        value: [{
            recipient: 'REPLACE-shared@contoso.com', recipientType: 'SharedMailbox', trustee: 'REPLACE-user@contoso.com', principalType: 'User', ...approvalTemplate,
            identityEvidence: { resolved: true, source: 'REPLACE-Entra ID', reference: 'REPLACE-evidence reference' },
            ownershipEvidence: { resolved: true, source: 'REPLACE-Mailbox owner', reference: 'REPLACE-evidence reference' }
        }]
    },
    sendOnBehalfDelegations: {
        title: 'Send on Behalf grants',
        how: 'One entry per mailbox and delegate, with identity and ownership evidence.',
        value: [{
            mailbox: 'REPLACE-shared@contoso.com', mailboxType: 'SharedMailbox', delegate: 'REPLACE-user@contoso.com', delegateType: 'User', ...approvalTemplate,
            identityEvidence: { resolved: true, source: 'REPLACE-Entra ID', reference: 'REPLACE-evidence reference' },
            ownershipEvidence: { resolved: true, source: 'REPLACE-Mailbox owner', reference: 'REPLACE-evidence reference' }
        }]
    },
    mailboxSafeSenders: {
        title: 'Mailbox safe senders',
        how: 'One entry per mailbox, listing approved senders and domains.',
        value: [{ mailbox: 'REPLACE-user@contoso.com', mailboxType: 'UserMailbox', senders: [{ kind: 'Sender', value: 'REPLACE-sender@partner.com', ...approvalTemplate }], domains: [] }]
    },
    organizationRelationships: {
        title: 'Partner free/busy sharing',
        how: 'One entry per partner. Sharing is limited to availability only.',
        value: [{
            identity: 'REPLACE-Partner name', enabled: true, partnerDomains: ['REPLACE-partner.com'], freeBusyAccessEnabled: true,
            freeBusyAccessLevel: 'AvailabilityOnly', freeBusyAccessScope: 'REPLACE-group@contoso.com',
            approval: { reference: 'REPLACE-CHG-1001', owner: 'REPLACE-owner@contoso.com', expiresOn: 'REPLACE-2026-12-31T00:00:00Z' },
            partnerAttestation: { status: 'Unverified' }
        }]
    },
    sharingPolicyBinding: {
        title: 'Sharing policies',
        how: 'Name each policy, the domains it allows, and which mailboxes use it, plus the disclosure approval.',
        value: {
            policies: [{ identity: 'REPLACE-Sharing policy', domains: ['REPLACE-partner.com: CalendarSharingFreeBusySimple'], enabled: true, isDefault: false }],
            defaultMailboxPolicy: 'REPLACE-Default sharing policy', explicitMailboxBindings: [],
            disclosureApproval: { Complete: true, IndependentlyApproved: true, Reference: 'REPLACE-CHG-1001', Owner: 'REPLACE-owner@contoso.com', ExpiresOn: 'REPLACE-2026-12-31T00:00:00Z' },
            partnerReadiness: 'Unverified'
        }
    },
    applicationAssignmentScope: {
        title: 'Application mailbox scope',
        how: 'This section carries Entra evidence and hashes from your identity owner. Build it with them using the Application assignment guide; do not hand-type it.',
        value: 'REPLACE-see the Application assignment scope guide'
    }
};

function initializeScopeBuilder(root) {
    const picker = root.querySelector('#scopePicker');
    if (!picker) {
        return;
    }
    const state = { scopes: [], preset: 'standard', domain: 'contoso.com', group: 'priority-users@contoso.com', secops: 'secops@contoso.com', optional: [], ...(readViewState().builder || {}) };
    const element = id => root.querySelector(`#${id}`);
    const quote = value => `'${value.replace(/'/g, "''")}'`;
    const listItems = (list, items) => list.replaceChildren(...items.map(html => {
        const item = document.createElement('li');
        item.innerHTML = html;
        return item;
    }));

    const areas = [...new Set(scopeCatalog.map(scope => scope.area))];
    areas.forEach(area => {
        const group = document.createElement('fieldset');
        group.className = 'scope-group';
        const legend = document.createElement('legend');
        legend.textContent = area;
        group.append(legend);
        scopeCatalog.filter(scope => scope.area === area).forEach(scope => {
            const label = document.createElement('label');
            label.className = 'scope-option';
            const box = document.createElement('input');
            box.type = 'checkbox';
            box.value = scope.id;
            box.checked = state.scopes.includes(scope.id);
            const name = document.createElement('code');
            name.textContent = scope.id;
            const text = document.createElement('span');
            text.className = 'scope-text';
            text.textContent = scope.text;
            const badges = document.createElement('span');
            badges.className = 'scope-badges';
            const badge = (label, tone) => {
                const tag = document.createElement('span');
                tag.className = `scope-badge ${tone}`;
                tag.textContent = label;
                badges.append(tag);
            };
            if (scope.atp) badge('Defender license', 'is-license');
            if (scope.presets) badge('Standard/Strict', 'is-preset');
            if (scope.required) badge('Needs details', 'is-required');
            if (scope.options) badge('Optional settings', 'is-optional');
            if (scope.governance) badge('Governance config', 'is-governance');
            label.append(box, name, badges, text);
            group.append(label);
        });
        picker.append(group);
    });

    function render() {
        const selected = scopeCatalog.filter(scope => state.scopes.includes(scope.id));
        const scopeArgument = selected.map(scope => quote(scope.id)).join(',');
        const governance = selected.some(scope => scope.governance);
        const presets = selected.some(scope => scope.presets);
        const required = [...new Set(selected.flatMap(scope => scope.required || []))];
        const optional = [...new Set(selected.flatMap(scope => scope.options || []))];
        state.optional = state.optional.filter(key => optional.includes(key));

        element('scopeArgument').textContent = selected.length ? `-Scope ${scopeArgument}` : 'Select at least one scope above.';
        const requirements = [];
        if (selected.some(scope => scope.atp)) requirements.push('Your licensing handoff must include <code>ATP_ENTERPRISE</code> (Defender for Office 365 Plan 1 or 2).');
        if (presets) requirements.push('Standard and Strict must already be turned on once in the Defender portal. Answer question 2.');
        if (required.length) requirements.push('These scopes need details in <code>workflowOptions</code>. Answer question 3.');
        if (governance) requirements.push('Governance scopes need the approved governance copy of the configuration, passed with <code>-ConfigurationPath</code>. See the <a href="#doc=EXCHANGE-GOVERNANCE.md" data-document="EXCHANGE-GOVERNANCE.md">governance guide</a>.');
        if (selected.length && !requirements.length) requirements.push('Nothing extra is needed for these scopes. Skip questions 2 and 3.');
        listItems(element('scopeRequirements'), requirements);

        element('presetNotNeeded').hidden = presets;
        element('presetBuilder').hidden = !presets;
        root.querySelectorAll('input[name="presetChoice"]').forEach(radio => { radio.checked = radio.value === state.preset; });
        element('presetDomain').value = state.domain;
        element('presetGroup').value = state.group;
        element('presetSecOps').value = state.secops;
        const presetSteps = state.preset === 'standard'
            ? [
                `Ask your Exchange admin to create an <strong>empty</strong> mail-enabled security group, <code>${escapeHtml(state.group)}</code>, with closed membership. It reserves the Strict slot; with no members nobody gets Strict.`,
                `Everyone in <code>${escapeHtml(state.domain)}</code> except <code>${escapeHtml(state.secops)}</code> gets Standard.`,
                'Later, to give someone Strict, add them to the group. No script change is needed.'
            ]
            : [
                `Make sure <code>${escapeHtml(state.group)}</code> exists as a mail-enabled security group with closed membership, owned by your security team.`,
                'Add the priority users your ticket names to that group. Only its members get Strict.',
                `Everyone else in <code>${escapeHtml(state.domain)}</code> except <code>${escapeHtml(state.secops)}</code> gets Standard.`
            ];
        listItems(element('presetSteps'), presetSteps);
        element('presetParameters').textContent = [
            `"PRIMARY_SMTP_DOMAIN": "${state.domain}",`,
            `"MAIL_ENABLED_PRIORITY_USERS_GROUP": "${state.group}",`,
            `"SECURITY_OPERATIONS_MAILBOX": "${state.secops}",`
        ].join('\n');

        const anyOptions = required.length + optional.length > 0;
        element('optionsNotNeeded').hidden = anyOptions;
        element('optionsBuilder').hidden = !anyOptions;
        const optionPicker = element('optionPicker');
        optionPicker.replaceChildren(...[...required, ...optional].map(key => {
            const label = document.createElement('label');
            label.className = 'scope-option';
            const box = document.createElement('input');
            box.type = 'checkbox';
            box.value = key;
            box.dataset.optionKey = key;
            box.checked = required.includes(key) || state.optional.includes(key);
            box.disabled = required.includes(key);
            const name = document.createElement('code');
            name.textContent = key;
            const text = document.createElement('span');
            text.className = 'scope-text';
            text.textContent = `${optionCatalog[key].title}${required.includes(key) ? ' (required)' : ' (optional)'}`;
            label.append(box, name, text);
            return label;
        }));
        const chosen = [...required, ...state.optional];
        listItems(element('optionSteps'), chosen.length
            ? chosen.map(key => `<code>${key}</code>: ${escapeHtml(optionCatalog[key].how)}`)
            : ['No extra settings chosen. Leave <code>workflowOptions</code> out of your parameter file.']);
        const block = Object.fromEntries(chosen.map(key => [key, optionCatalog[key].value]));
        element('optionJson').textContent = chosen.length ? `"workflowOptions": ${JSON.stringify(block, null, 2)},` : '';
        element('optionJson').parentElement.hidden = !chosen.length;

        root.querySelectorAll('[data-scope-arg]').forEach(span => { span.textContent = scopeArgument || "'Transport'"; });
        root.querySelectorAll('[data-config-arg]').forEach(span => {
            span.textContent = governance ? "\n    -ConfigurationPath 'D:\\ExchangeChanges\\contoso.exchange-only.governance.json' `" : '';
        });

        const checklist = [];
        checklist.push(selected.length ? `Scope: <code>${escapeHtml(scopeArgument)}</code>. Steps 4 and 5 already use it.` : 'Go back to Step 2 and choose at least one scope.');
        if (presets) checklist.push(`Set <code>PRIMARY_SMTP_DOMAIN</code>, <code>MAIL_ENABLED_PRIORITY_USERS_GROUP</code>, and <code>SECURITY_OPERATIONS_MAILBOX</code> to the values from question 2.`);
        if (chosen.length) checklist.push(`Paste the <code>workflowOptions</code> block from question 3 and replace every <code>REPLACE-</code> value. The readiness check refuses any that remain.`);
        if (governance) checklist.push('Copy the approved governance configuration into your protected folder; the readiness command in Step 4 already passes it with <code>-ConfigurationPath</code>.');
        const step3 = element('step3Checklist');
        if (step3) {
            listItems(step3, checklist);
        }

        const confirm = root.querySelector('[data-wizard-panel="1"] [data-wizard-complete]');
        confirm.disabled = !selected.length;
        if (!selected.length && confirm.checked) {
            confirm.checked = false;
            confirm.dispatchEvent(new Event('change'));
        }
        saveViewState({ builder: state });
        addCopyButtons(root.querySelector('[data-wizard-panel="1"]'));
    }

    picker.addEventListener('change', event => {
        if (event.target.type !== 'checkbox') return;
        state.scopes = Array.from(picker.querySelectorAll('input:checked')).map(box => box.value);
        render();
    });
    root.querySelectorAll('input[name="presetChoice"]').forEach(radio => radio.addEventListener('change', () => { state.preset = radio.value; render(); }));
    [['presetDomain', 'domain'], ['presetGroup', 'group'], ['presetSecOps', 'secops']].forEach(([id, key]) => {
        element(id).addEventListener('input', event => {
            state[key] = event.target.value.trim();
            render();
            element(id).focus();
        });
    });
    element('optionPicker').addEventListener('change', event => {
        const key = event.target.dataset.optionKey;
        if (!key || event.target.disabled) return;
        state.optional = event.target.checked ? [...new Set([...state.optional, key])] : state.optional.filter(item => item !== key);
        render();
    });
    render();
}

function escapeHtml(value) {
    const holder = document.createElement('span');
    holder.textContent = value;
    return holder.innerHTML;
}

function initializeWizard() {
    const template = document.getElementById('changeWizardTemplate');
    const mount = document.getElementById('wizardMount');
    const intro = document.getElementById('wizardIntro');
    const beginButton = document.getElementById('wizardBegin');
    if (template && mount) {
        mount.append(template.content.cloneNode(true));
    }
    changeWizard = document.getElementById('changeWizard');
    if (!changeWizard) {
        return;
    }
    initializeScopeBuilder(changeWizard);

    const panels = Array.from(changeWizard.querySelectorAll('[data-wizard-panel]'));
    const stepButtons = Array.from(changeWizard.querySelectorAll('[data-wizard-go]'));
    const progressText = changeWizard.querySelector('#wizardProgressText');
    const progressBar = changeWizard.querySelector('#wizardProgressBar');
    const progressFill = progressBar.querySelector('span');
    const backButton = changeWizard.querySelector('#wizardBack');
    const nextButton = changeWizard.querySelector('#wizardNext');
    const stepStatus = changeWizard.querySelector('#wizardStepStatus');
    const completionMessage = changeWizard.querySelector('.wizard-finish');
    const saved = readViewState().wizard || {};
    const completed = panels.map((_, index) => Array.isArray(saved.completed) && saved.completed[index] === true);
    let currentStep = Number.isInteger(saved.step) && saved.step >= 0 && saved.step < panels.length ? saved.step : 0;
    // Never restore past the first unconfirmed step, so the confirmation gate still holds.
    const firstOpen = completed.indexOf(false);
    if (firstOpen !== -1 && currentStep > firstOpen) {
        currentStep = firstOpen;
    }
    let wizardFinished = false;
    if (saved.started) {
        intro.hidden = true;
        mount.hidden = false;
    }

    function renderWizard({ focusHeading = false } = {}) {
        const currentTitle = panels[currentStep].querySelector('h2').textContent;
        panels.forEach((panel, index) => {
            const isCurrent = index === currentStep;
            panel.hidden = !isCurrent;
            panel.classList.toggle('is-current', isCurrent);
            panel.querySelector('[data-wizard-complete]').checked = completed[index];
        });

        stepButtons.forEach((button, index) => {
            const isCurrent = index === currentStep;
            button.disabled = index > currentStep && !completed[index - 1];
            button.classList.toggle('is-current', isCurrent);
            button.classList.toggle('is-complete', completed[index]);
            if (isCurrent) {
                button.setAttribute('aria-current', 'step');
            } else {
                button.removeAttribute('aria-current');
            }
        });

        progressText.textContent = `Step ${currentStep + 1} of ${panels.length}: ${currentTitle}`;
        progressBar.setAttribute('aria-valuenow', String(currentStep + 1));
        progressFill.style.width = `${((currentStep + 1) / panels.length) * 100}%`;
        backButton.disabled = currentStep === 0;
        nextButton.disabled = !completed[currentStep];
        nextButton.textContent = currentStep === panels.length - 1 ? 'Finish' : 'Confirm and continue';
        stepStatus.textContent = completed[currentStep]
            ? currentStep === panels.length - 1
                ? 'Final step confirmed.'
                : 'Step confirmed. Continue when ready.'
            : 'Review this step, then confirm to continue.';
        completionMessage.hidden = !wizardFinished;
        saveViewState({ wizard: { started: !mount.hidden, step: currentStep, completed: [...completed] } });

        if (focusHeading) {
            panels[currentStep].querySelector('h2').focus();
        }
    }

    panels.forEach((panel, index) => {
        panel.querySelector('[data-wizard-complete]').addEventListener('change', event => {
            completed[index] = event.target.checked;
            if (!completed[index]) {
                wizardFinished = false;
                for (let later = index + 1; later < completed.length; later += 1) {
                    completed[later] = false;
                }
            }
            renderWizard();
        });
    });

    stepButtons.forEach(button => {
        button.addEventListener('click', () => {
            const destination = Number(button.dataset.wizardGo);
            if (!button.disabled && destination !== currentStep) {
                currentStep = destination;
                renderWizard({ focusHeading: true });
            }
        });
    });

    backButton.addEventListener('click', () => {
        if (currentStep > 0) {
            currentStep -= 1;
            renderWizard({ focusHeading: true });
        }
    });

    nextButton.addEventListener('click', () => {
        if (!completed[currentStep]) {
            return;
        }
        if (currentStep < panels.length - 1) {
            currentStep += 1;
            renderWizard({ focusHeading: true });
        } else {
            wizardFinished = true;
            stepStatus.textContent = 'Walkthrough complete. Go-live still requires an approved evidence decision.';
            completionMessage.hidden = false;
            completionMessage.focus();
        }
    });

    beginButton.addEventListener('click', () => {
        intro.hidden = true;
        mount.hidden = false;
        renderWizard();
        panels[currentStep].querySelector('h2').focus();
        window.scrollTo(0, 0);
    });

    renderWizard();
}

function openDrawer() {
    lastFocusedElement = document.activeElement;
    drawerBackdrop.hidden = false;
    requestAnimationFrame(() => {
        drawerBackdrop.classList.add('is-open');
        navigationDrawer.classList.add('is-open');
        requestAnimationFrame(() => drawerClose.focus());
    });
    navigationDrawer.setAttribute('aria-hidden', 'false');
    menuToggle.setAttribute('aria-expanded', 'true');
    menuToggle.setAttribute('aria-label', 'Close navigation');
    document.body.classList.add('drawer-open');
}

function closeDrawer() {
    drawerBackdrop.classList.remove('is-open');
    navigationDrawer.classList.remove('is-open');
    navigationDrawer.setAttribute('aria-hidden', 'true');
    menuToggle.setAttribute('aria-expanded', 'false');
    menuToggle.setAttribute('aria-label', 'Open navigation');
    document.body.classList.remove('drawer-open');
    window.setTimeout(() => {
        drawerBackdrop.hidden = true;
    }, 300);
    if (lastFocusedElement) {
        lastFocusedElement.focus();
    }
}

function showSection(sectionId, selectedNavItem) {
    document.querySelectorAll('.section').forEach(section => {
        section.classList.remove('active');
    });

    const selectedSection = document.getElementById(sectionId);
    if (selectedSection) {
        selectedSection.classList.add('active');
        window.scrollTo(0, 0);
        if (sectionId !== 'documentViewer') {
            saveViewState({ section: sectionId });
        }
    }

    navItems.forEach(item => {
        item.classList.remove('active');
        item.setAttribute('aria-current', 'false');
    });
    if (selectedNavItem) {
        selectedNavItem.classList.add('active');
        selectedNavItem.setAttribute('aria-current', 'page');
    }
    closeDrawer();
}

menuToggle.addEventListener('click', () => {
    if (navigationDrawer.classList.contains('is-open')) {
        closeDrawer();
    } else {
        openDrawer();
    }
});

drawerClose.addEventListener('click', closeDrawer);
drawerBackdrop.addEventListener('click', closeDrawer);

navItems.forEach(item => {
    item.addEventListener('click', () => showSection(item.dataset.section, item));
});

sectionLinks.forEach(link => {
    link.addEventListener('click', event => {
        event.preventDefault();
        const sectionId = link.dataset.sectionLink;
        const selectedNavItem = document.querySelector(`.nav-item[data-section="${sectionId}"]`);
        showSection(sectionId, selectedNavItem);
    });
});

document.addEventListener('click', event => {
    const link = event.target.closest('[data-document]');
    if (!link) {
        return;
    }
    event.preventDefault();
    const fileName = link.dataset.document;
    const section = link.dataset.documentSection || '';
    if (activeDocument === fileName && document.getElementById('documentViewer').classList.contains('active')) {
        const target = Array.from(document.getElementById('documentContent').querySelectorAll('[id]'))
            .find(element => element.id === section);
        target?.scrollIntoView({ behavior: 'smooth' });
        const route = new URLSearchParams({ doc: fileName });
        if (section) {
            route.set('section', section);
        }
        history.replaceState(null, '', `#${route.toString()}`);
        return;
    }
    const route = new URLSearchParams({ doc: fileName });
    if (section) {
        route.set('section', section);
    }
    window.location.hash = route.toString();
});

document.getElementById('documentBack').addEventListener('click', () => {
    history.replaceState(null, '', `${window.location.pathname}${window.location.search}`);
    showSection(previousSection, document.querySelector(`.nav-item[data-section="${previousSection}"]`));
});

window.addEventListener('hashchange', routeHash);

document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && navigationDrawer.classList.contains('is-open')) {
        closeDrawer();
    }
});

copyCloneUrl.addEventListener('click', async () => {
    const cloneCommand = 'git clone https://github.com/chadhage/enterprise-scale-exchange-online.git';
    try {
        await navigator.clipboard.writeText(cloneCommand);
        copyStatus.textContent = 'Clone command copied.';
    } catch {
        copyStatus.textContent = 'Copy unavailable. Select the command to copy it.';
    }
});

initializeWizard();
addCopyButtons(document);
markExternalLinks(document);
const restoredSection = readViewState().section;
if (!new URLSearchParams(window.location.hash.slice(1)).get('doc') && restoredSection && document.getElementById(restoredSection)) {
    previousSection = restoredSection;
    showSection(restoredSection, document.querySelector(`.nav-item[data-section="${restoredSection}"]`));
}
routeHash();
