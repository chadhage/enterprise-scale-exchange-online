#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement is not installed and must never be imported. Get-AntiPhishPolicy is
    # reached only through the supplied collection seam, so every collection here is a scriptblock
    # returning canned policies or throwing a canned failure.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # Assigning before unrolling matters: the registry is returned as one read-only collection
    # deliberately protected from pipeline unrolling, so it is read by index rather than by pipe.
    $script:ControlRegistry = @(Get-BaselineControlRegistry -Profile Historical)[0]
    $script:PriorityAccountRegistration = @(foreach ($entry in $script:ControlRegistry) {
            if ($entry.ControlId -ceq 'MDO-009') { $entry }
        })[0]

    function New-AntiPhishPolicy {
        [CmdletBinding()]
        param(
            [object]$Name = 'Contoso Strict',

            [object]$Enabled = $true,

            [object]$EnableTargetedUserProtection = $true,

            [object]$EnableTargetedDomainsProtection = $true,

            [object]$TargetedUsersToProtect = @('Chief Executive;ceo@contoso.com'),

            [object]$TargetedDomainsToProtect = @('contoso.com'),

            [object]$ExcludedSenders = @('partner@fabrikam.example'),

            [object]$ExcludedDomains = @('lab.fabrikam.example')
        )

        return [pscustomobject]@{
            EnableTargetedDomainsProtection = $EnableTargetedDomainsProtection
            EnableTargetedUserProtection    = $EnableTargetedUserProtection
            Enabled                         = $Enabled
            ExcludedDomains                 = $ExcludedDomains
            ExcludedSenders                 = $ExcludedSenders
            Identity                        = $Name
            Name                            = $Name
            TargetedDomainsToProtect        = $TargetedDomainsToProtect
            TargetedUsersToProtect          = $TargetedUsersToProtect
        }
    }

    # MDO-001: the impersonation protection the baseline resolves. The protected users are the
    # priority identities the tenant must protect; the protected domains and the approved
    # exceptions are matched exactly, each exception granted on the one member it names.
    $script:DesiredImpersonationProtection = [pscustomobject]@{
        enabled            = $true
        protectedUsers     = @('ceo@contoso.com')
        protectedDomains   = @('contoso.com')
        approvedExceptions = @(
            [pscustomobject]@{
                exceptionType      = 'TrustedSender'
                value              = 'partner@fabrikam.example'
                owner              = 'Security Operations'
                ticket             = 'SEC-1042'
                expirationDateTime = '2026-12-31T00:00:00Z'
                justification      = 'Contracted partner sends on behalf of the chief executive.'
            }
            [pscustomobject]@{
                exceptionType      = 'TrustedDomain'
                value              = 'lab.fabrikam.example'
                owner              = 'Security Operations'
                ticket             = 'SEC-1043'
                expirationDateTime = '2026-12-31T00:00:00Z'
                justification      = 'Phishing simulation range operated under contract.'
            }
        )
    }

    function New-AntiPhishPolicyWithout {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$Member
        )

        $policy = [ordered]@{
            EnableTargetedDomainsProtection = $true
            EnableTargetedUserProtection    = $true
            Enabled                         = $true
            ExcludedDomains                 = @('lab.fabrikam.example')
            ExcludedSenders                 = @('partner@fabrikam.example')
            Name                            = 'Contoso Strict'
            TargetedDomainsToProtect        = @('contoso.com')
            TargetedUsersToProtect          = @('Chief Executive;ceo@contoso.com')
        }

        $policy.Remove($Member)

        return [pscustomobject]$policy
    }

    function New-ImpersonationEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyCollection()]
            [object]$Policy
        )

        return Get-PriorityAccountEvidence -AntiPhishPolicyCollection { $Policy }.GetNewClosure()
    }

    function New-PartialImpersonationEvidence {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [AllowNull()]
            [object]$Payload
        )

        return New-BaselineEvidence -ControlId 'MDO-009' -Source 'ExchangeOnline' `
            -Command 'Get-AntiPhishPolicy' -Value $Payload
    }

    function Get-VerdictFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Result
        )

        return '{0}|golive={1}|reason={2}' -f $Result.Status, $Result.GoLiveSuccess, $Result.Reason
    }

    function Get-ResultFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Result
        )

        return '{0}|{1}|normalized={2}|golive={3}|reason={4}|evidence={5}:{6}' -f `
            $Result.ControlId,
        $Result.Status,
        $Result.Normalized,
        $Result.GoLiveSuccess,
        $Result.Reason,
        $Result.Evidence.Command,
        $Result.Evidence.ControlId
    }

    function Get-EvidenceFold {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Evidence
        )

        $memberName = [string[]]@($Evidence.Keys)
        [System.Array]::Sort($memberName, [System.StringComparer]::Ordinal)

        return '{0}|{1}|{2}|collected={3}|failure={4}|{5}|members={6}' -f `
            $Evidence.ControlId,
        $Evidence.Source,
        $Evidence.Command,
        $Evidence.Collected,
        $Evidence.FailureReason,
        (ConvertTo-CanonicalJson -InputObject $Evidence.Value),
        ($memberName -join ',')
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'MDO-005-A1 Impersonation protection collector' {

    Context 'Negative: the collector the registry declares must be the collector the module ships' {

        It 'exports the collector MDO-009 is registered against' {
            # Arrange
            $registered = $script:PriorityAccountRegistration.Collector

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' observes impersonation protection of the priority identities, and a collector that is named but not shipped is a control nobody collects"
        }
    }

    Context 'Negative: the collector must be given the service call to make' {

        It 'refuses a collection with no anti-phish policy to read' {
            # Arrange
            $noCollection = $null

            # Act
            $act = { Get-PriorityAccountEvidence -AntiPhishPolicyCollection $noCollection }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'AntiPhishPolicyCollectionRequired*' `
                    -Because 'the anti-phish policies are the only place the protected identities, the protected domains and the trusted exceptions are recorded, and a record assembled without reading them reports an impersonation posture nobody looked up'
        }
    }

    Context 'Negative: a service that refused is never an observation' {

        It 'records a collection that threw as an uncollected observation instead of propagating it' {
            # Arrange
            $refusing = { throw 'The term Get-AntiPhishPolicy is not recognized in this session.' }

            # Act
            $evidence = Get-PriorityAccountEvidence -AntiPhishPolicyCollection $refusing

            # Assert
            ('collected={0}|failure={1}' -f $evidence.Collected, $evidence.FailureReason) |
                Should -BeLike 'collected=False|failure=CollectionFailed:*' `
                    -Because 'an exception here discards every other control in the run, and a refused command that is not recorded as refused reads downstream exactly like a tenant that was read and found protecting its priority identities'
        }
    }

    Context 'Negative: a tenant that returned nothing is an observation, not a failed collection' {

        It 'records a tenant that holds no anti-phish policy at all as collected' {
            # Arrange
            $empty = { }

            # Act
            $evidence = Get-PriorityAccountEvidence -AntiPhishPolicyCollection $empty

            # Assert
            ('collected={0}|failure={1}|{2}' -f $evidence.Collected, $evidence.FailureReason, (ConvertTo-CanonicalJson -InputObject $evidence.Value)) |
                Should -BeExactly 'collected=True|failure=|{"AntiPhishPolicy":[]}' `
                    -Because 'a tenant that has never configured impersonation protection is the exact finding this control exists to report, and calling it a collection failure hides that finding behind an infrastructure excuse'
        }
    }

    Context 'Negative: the observation cannot be edited after it is made' {

        It 'returns a record that rejects assignment' {
            # Arrange
            $evidence = Get-PriorityAccountEvidence -AntiPhishPolicyCollection { @(New-AntiPhishPolicy -Enabled $false) }

            # Act
            $act = { $evidence.Value['AntiPhishPolicy'] = @() }

            # Assert
            $act |
                Should -Throw `
                    -Because 'raw evidence a caller can rewrite is not evidence of the tenant, it is evidence of whatever the caller wanted the tenant to be'
        }
    }

    Context 'Positive: one run of the collection is one record of exactly what the command returned' {

        It 'records every policy whole under its declared name, under the control, source and command the registry declares' {
            # Arrange
            $strictPolicy = New-AntiPhishPolicy -Name ' Contoso Strict ' `
                -TargetedUsersToProtect @('Chief Executive;CEO@Contoso.com') `
                -TargetedDomainsToProtect @('Contoso.COM.') `
                -ExcludedSenders @('SMTP:Partner@Fabrikam.Example') `
                -ExcludedDomains @('lab.fabrikam.example')
            $retiredPolicy = New-AntiPhishPolicy -Name 'Legacy pilot' -Enabled $false `
                -EnableTargetedUserProtection $false -EnableTargetedDomainsProtection $false `
                -TargetedUsersToProtect @() -TargetedDomainsToProtect @() -ExcludedSenders @() -ExcludedDomains @()
            $expected = 'MDO-009|ExchangeOnline|Get-AntiPhishPolicy|collected=True|failure=|' +
            '{"AntiPhishPolicy":[' +
            '{"EnableTargetedDomainsProtection":true,"EnableTargetedUserProtection":true,"Enabled":true,' +
            '"ExcludedDomains":["lab.fabrikam.example"],"ExcludedSenders":["SMTP:Partner@Fabrikam.Example"],' +
            '"Identity":" Contoso Strict ","Name":" Contoso Strict ","TargetedDomainsToProtect":["Contoso.COM."],' +
            '"TargetedUsersToProtect":["Chief Executive;CEO@Contoso.com"]},' +
            '{"EnableTargetedDomainsProtection":false,"EnableTargetedUserProtection":false,"Enabled":false,' +
            '"ExcludedDomains":[],"ExcludedSenders":[],"Identity":"Legacy pilot","Name":"Legacy pilot",' +
            '"TargetedDomainsToProtect":[],"TargetedUsersToProtect":[]}]}' +
            '|members=Collected,CollectedAtUtc,Command,ControlId,FailureReason,Source,Value'

            # Act
            $evidence = Get-PriorityAccountEvidence -AntiPhishPolicyCollection { @($strictPolicy, $retiredPolicy) }.GetNewClosure()

            # Assert
            (Get-EvidenceFold -Evidence $evidence) |
                Should -BeExactly $expected `
                    -Because 'the collector owns what was observed and holds no opinion about what it means, so each policy has to survive collection with its casing, its whitespace, its routing prefix, its trailing root label, its display-name prefix and its unrelated sibling members intact, and the disabled policy has to survive too; a collector that dropped the disabled policies or narrowed each policy to the members the control decides on would decide the impersonation posture before the evaluator ever saw it'
        }
    }
}

Describe 'MDO-005-A2 Impersonation protection evaluator' {

    Context 'Negative: the evaluator the registry declares must be the evaluator the module ships' {

        It 'exports the evaluator MDO-009 is registered against' {
            # Arrange
            $registered = $script:PriorityAccountRegistration.Evaluator

            # Act
            $exported = @(Get-Command -Module 'ExchangeOnlineBaseline.Common' -Name $registered -ErrorAction SilentlyContinue)

            # Assert
            $exported.Count |
                Should -Be 1 `
                    -Because "the registry declares '$registered' decides impersonation protection, and a control the run cannot decide is a control the go-live gate never hears about"
        }
    }

    Context 'Negative: the evaluator must be given an observation and the protection the baseline resolved' {

        It 'refuses a decision with no evidence' {
            # Arrange
            $noEvidence = $null

            # Act
            $act = { Test-PriorityAccountControl -Evidence $noEvidence -DesiredState $script:DesiredImpersonationProtection }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceRequired*' `
                    -Because 'a verdict reached over no observation counts towards the baseline exactly as much as a real one'
        }

        It 'refuses evidence collected for another control' {
            # Arrange
            $foreign = New-BaselineEvidence -ControlId 'MDO-003' -Source 'ExchangeOnline' `
                -Command 'Get-ATPBuiltInProtectionRule' -Value @(New-AntiPhishPolicy)

            # Act
            $act = { Test-PriorityAccountControl -Evidence $foreign -DesiredState $script:DesiredImpersonationProtection }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'EvidenceControlMismatch*' `
                    -Because 'a verdict about who the tenant protects from impersonation cannot be reached from a record collected to answer a different question'
        }

        It 'refuses a decision that names no resolved desired impersonation protection state' {
            # Arrange
            $evidence = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy)

            # Act
            $act = { Test-PriorityAccountControl -Evidence $evidence -DesiredState $null }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredImpersonationProtectionStateRequired*' `
                    -Because 'the card demands the protected identities, domains and exceptions match what was configured, and an evaluator handed no desired state decides against whatever it defaults to rather than against what was approved'
        }

        It 'refuses a desired state that resolves no protected user' {
            # Arrange
            $evidence = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy)
            $unprotected = [pscustomobject]@{ protectedUsers = @(); protectedDomains = @('contoso.com'); approvedExceptions = @() }

            # Act
            $act = { Test-PriorityAccountControl -Evidence $evidence -DesiredState $unprotected }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredImpersonationProtectedUserRequired*' `
                    -Because 'impersonation protection that names no priority identity protects nobody, and comparing a tenant against an empty identity list passes exactly the tenant that protects nobody either'
        }

        It 'refuses a desired state that declares no approved exception register at all' {
            # Arrange
            $evidence = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy)
            $unregistered = [pscustomobject]@{ protectedUsers = @('ceo@contoso.com'); protectedDomains = @('contoso.com') }

            # Act
            $act = { Test-PriorityAccountControl -Evidence $evidence -DesiredState $unregistered }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'DesiredImpersonationExceptionsRequired*' `
                    -Because 'a baseline that approves no exception and a baseline that never declared the register read identically once the member is absent, and only one of them is a decision somebody made'
        }

        It 'refuses an approved exception granted on a member the exception contract does not declare' {
            # Arrange
            $evidence = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy)
            $unknown = [pscustomobject]@{
                protectedUsers     = @('ceo@contoso.com')
                protectedDomains   = @('contoso.com')
                approvedExceptions = @([pscustomobject]@{ exceptionType = 'TrustedIpAddress'; value = '198.51.100.7' })
            }

            # Act
            $act = { Test-PriorityAccountControl -Evidence $evidence -DesiredState $unknown }

            # Assert
            $act |
                Should -Throw -ExpectedMessage 'UnknownImpersonationExceptionType*' `
                    -Because 'an approval granted on a member an anti-phish policy has no such exception for is an approval that can never be matched, and silently dropping it would let the register claim an exemption the tenant is not actually holding'
        }
    }

    Context 'Negative: a collection that did not happen is never a decided control' {

        It 'decides an uncollected record as an error rather than a verdict' {
            # Arrange
            $refused = Get-PriorityAccountEvidence -AntiPhishPolicyCollection { throw 'The operation was throttled and could not be completed.' }

            # Act
            $result = Test-PriorityAccountControl -Evidence $refused -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeLike 'Error|golive=False|reason=EvidenceCollectionFailed:*' `
                    -Because 'a control the run never managed to observe must cost the run its go-live, because the alternative is that throttling the tenant is the cheapest way to pass it'
        }
    }

    Context 'Negative: a record that never observed the policies decides nothing about them' {

        It 'decides a record carrying no anti-phish policy observation as an error' {
            # Arrange
            $partial = New-PartialImpersonationEvidence -Payload ([ordered]@{ AntiPhishRule = @(New-AntiPhishPolicy) })

            # Act
            $result = Test-PriorityAccountControl -Evidence $partial -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ImpersonationProtectionEvidenceIncomplete: the record carries no 'AntiPhishPolicy' observation." `
                    -Because 'an absent observation is not an observation that the tenant holds no anti-phish policy, and reading it as one decides the control from a command nobody ran'
        }

        It 'decides an observed policy carrying no <Member> member as an error' -ForEach @(
            @{ Member = 'Name' }
            @{ Member = 'Enabled' }
            @{ Member = 'EnableTargetedUserProtection' }
            @{ Member = 'EnableTargetedDomainsProtection' }
            @{ Member = 'TargetedUsersToProtect' }
            @{ Member = 'TargetedDomainsToProtect' }
            @{ Member = 'ExcludedSenders' }
            @{ Member = 'ExcludedDomains' }
        ) {
            # Arrange
            $incomplete = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicyWithout -Member $Member)

            # Act
            $result = Test-PriorityAccountControl -Evidence $incomplete -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Error|golive=False|reason=ImpersonationProtectionEvidenceIncomplete: an observed AntiPhishPolicy carries no '$Member' member." `
                    -Because 'an absent member read as empty or as switched off reports a policy protecting nobody and excluding nobody, which is indistinguishable from a policy the collector simply did not carry'
        }
    }

    Context 'Negative: a tenant with no enabled anti-phish policy fails' {

        It 'fails a tenant whose only anti-phish policy is disabled' {
            # Arrange
            $dormant = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy -Enabled $false)

            # Act
            $result = Test-PriorityAccountControl -Evidence $dormant -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly 'Fail|golive=False|reason=ImpersonationProtectionDrift: the tenant holds no enabled anti-phish policy.' `
                    -Because 'a policy that is switched off protects nobody, and a control that read the identities out of a dormant policy would report impersonation protection the tenant is not applying to a single message'
        }
    }

    Context 'Negative: a priority identity no enabled policy protects fails' {

        It 'fails a tenant whose priority identity is protected only by a disabled policy' {
            # Arrange
            $dormantProtection = New-ImpersonationEvidence -Policy @(
                (New-AntiPhishPolicy -TargetedUsersToProtect @()),
                (New-AntiPhishPolicy -Name 'Legacy pilot' -Enabled $false -TargetedDomainsToProtect @() -ExcludedSenders @() -ExcludedDomains @())
            )

            # Act
            $result = Test-PriorityAccountControl -Evidence $dormantProtection -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ImpersonationProtectionDrift: no enabled policy protects 'ceo@contoso.com' from user impersonation." `
                    -Because 'the identity is named in a policy nobody applies, and counting it would report the chief executive protected against impersonation by a policy that is switched off'
        }

        It 'fails a tenant whose priority identity is listed by a policy with user impersonation protection switched off' {
            # Arrange
            $switchedOff = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy -EnableTargetedUserProtection $false)

            # Act
            $result = Test-PriorityAccountControl -Evidence $switchedOff -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ImpersonationProtectionDrift: no enabled policy protects 'ceo@contoso.com' from user impersonation." `
                    -Because 'the list of protected users is inert while the switch that applies it is off, and a control that read the list alone reports protection nobody is receiving'
        }
    }

    Context 'Negative: protected domains and trusted exceptions that differ from the configuration fail' {

        It 'fails a tenant whose enabled policies protect none of the configured custom domains' {
            # Arrange
            $unprotectedDomain = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy -TargetedDomainsToProtect @())

            # Act
            $result = Test-PriorityAccountControl -Evidence $unprotectedDomain -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ImpersonationProtectionDrift: no enabled policy protects the domain 'contoso.com' from domain impersonation." `
                    -Because 'a custom protected domain the configuration names and the tenant does not protect is exactly the drift the card requires be matched'
        }

        It 'fails a policy protecting a domain the baseline never approved' {
            # Arrange
            $surplusDomain = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy -TargetedDomainsToProtect @('contoso.com', 'fabrikam.example'))

            # Act
            $result = Test-PriorityAccountControl -Evidence $surplusDomain -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ImpersonationProtectionDrift: the policy 'Contoso Strict' protects unapproved domain 'fabrikam.example'." `
                    -Because 'the card requires the custom protected domains exactly match the configuration, and a domain nobody approved quarantines mail from a partner the tenant never decided to treat as impersonated'
        }

        It 'fails a policy trusting a sender the baseline never approved' {
            # Arrange
            $surplusSender = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy -ExcludedSenders @('partner@fabrikam.example', 'attacker@fabrikam.example'))

            # Act
            $result = Test-PriorityAccountControl -Evidence $surplusSender -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ImpersonationProtectionDrift: the policy 'Contoso Strict' trusts unapproved sender 'attacker@fabrikam.example'." `
                    -Because 'a trusted sender nobody approved is a standing exemption from impersonation protection, which is the one change to this control that makes the tenant weaker without touching a single protected identity'
        }

        It 'fails a policy trusting a domain the baseline never approved' {
            # Arrange
            $surplusDomain = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy -ExcludedDomains @('lab.fabrikam.example', 'fabrikam.example'))

            # Act
            $result = Test-PriorityAccountControl -Evidence $surplusDomain -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ImpersonationProtectionDrift: the policy 'Contoso Strict' trusts unapproved domain 'fabrikam.example'." `
                    -Because 'an approval for a laboratory subdomain can never approve trusting the whole domain above it, and the broad exemption is exactly the one an inexact comparison would hide'
        }

        It 'fails a tenant applying none of the approved trusted senders' {
            # Arrange
            $missingSender = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy -ExcludedSenders @())

            # Act
            $result = Test-PriorityAccountControl -Evidence $missingSender -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ImpersonationProtectionDrift: no enabled policy trusts approved sender 'partner@fabrikam.example'." `
                    -Because 'the card requires the trusted exceptions exactly match the configuration, so an approval the tenant is not applying means the register no longer describes the tenant it was approved for'
        }

        It 'fails a tenant applying none of the approved trusted domains' {
            # Arrange
            $missingDomain = New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy -ExcludedDomains @())

            # Act
            $result = Test-PriorityAccountControl -Evidence $missingDomain -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-VerdictFold -Result $result) |
                Should -BeExactly "Fail|golive=False|reason=ImpersonationProtectionDrift: no enabled policy trusts approved domain 'lab.fabrikam.example'." `
                    -Because 'an approved exception the tenant does not hold is a register that has drifted from the tenant, which the card requires be matched in both directions'
        }
    }

    Context 'Negative: the verdict cannot be edited after it is reached' {

        It 'returns a result that rejects assignment' {
            # Arrange
            $result = Test-PriorityAccountControl `
                -Evidence (New-ImpersonationEvidence -Policy @(New-AntiPhishPolicy -TargetedUsersToProtect @())) `
                -DesiredState $script:DesiredImpersonationProtection

            # Act
            $act = { $result['Status'] = 'Pass' }

            # Assert
            $act |
                Should -Throw `
                    -Because 'a verdict a later stage can rewrite is a verdict the go-live gate cannot rely on'
        }
    }

    Context 'Positive: every priority identity protected and the domains and exceptions exactly as configured is one go-live-successful pass' {

        It 'passes a tenant whose enabled policies together protect the priority identities and hold exactly the approved domains and exceptions' {
            # Arrange
            $strictPolicy = New-AntiPhishPolicy -Name ' Contoso Strict ' `
                -TargetedUsersToProtect @('Chief Executive;CEO@Contoso.com', 'ceo@contoso.com', 'Head of Legal;legal@contoso.com') `
                -TargetedDomainsToProtect @('Contoso.COM.') `
                -ExcludedSenders @('SMTP:Partner@Fabrikam.Example') `
                -ExcludedDomains @()
            $executivePolicy = New-AntiPhishPolicy -Name 'Contoso Executives' `
                -TargetedUsersToProtect @() -TargetedDomainsToProtect @() -ExcludedSenders @() `
                -ExcludedDomains @('LAB.Fabrikam.Example.')
            $retiredPolicy = New-AntiPhishPolicy -Name 'Legacy pilot' -Enabled $false `
                -TargetedUsersToProtect @() -TargetedDomainsToProtect @('fabrikam.example') `
                -ExcludedSenders @('attacker@fabrikam.example') -ExcludedDomains @('fabrikam.example')
            $configured = New-ImpersonationEvidence -Policy @($retiredPolicy, $strictPolicy, $executivePolicy)
            $expected = 'MDO-009|Pass|normalized=True|golive=True|reason=|evidence=Get-AntiPhishPolicy:MDO-009'

            # Act
            $result = Test-PriorityAccountControl -Evidence $configured -DesiredState $script:DesiredImpersonationProtection

            # Assert
            (Get-ResultFold -Result $result) |
                Should -BeExactly $expected `
                    -Because 'the declared comparisons trim, lower the casing, drop a trailing root label, strip an SMTP routing prefix and the display-name prefix Exchange Online reports a protected user under, and collapse duplicates, so the tenant reported back in its own formatting is the tenant the baseline asked for; the protection may be spread across several enabled policies, a priority identity protected beyond the configured list is protection rather than drift, and the disabled policy trusting an attacker is one this control must leave entirely alone'
        }
    }
}
