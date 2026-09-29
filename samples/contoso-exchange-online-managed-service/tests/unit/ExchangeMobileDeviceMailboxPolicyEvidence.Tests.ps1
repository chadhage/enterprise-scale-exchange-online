#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:ManifestPath = Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1'
    Import-Module -Name $script:ManifestPath -Force -DisableNameChecking -ErrorAction Stop
    $script:SyntheticAuthority = 'SyntheticNonAuthoritativeFixture'

    function New-SyntheticMobileSetting {
        param([string]$Name = 'AlphanumericPasswordRequired', [string]$Type = 'Boolean', [object]$Value = $true)
        [pscustomobject][ordered]@{ Name = $Name; Type = $Type; Value = $Value; Authority = $script:SyntheticAuthority }
    }

    function Copy-SyntheticMobileSettings {
        param([Parameter(Mandatory)][object[]]$Settings)
        @($Settings | ForEach-Object {
            [pscustomobject][ordered]@{
                Name = $_.Name
                Type = $_.Type
                Value = $_.Value
                Authority = $_.Authority
            }
        })
    }

    function New-SyntheticMobilePolicy {
        param([string]$Identity = 'Synthetic-Managed-Mobile-Policy')
        [pscustomobject][ordered]@{
            Identity = $Identity
            IsDefault = $false
            Settings = @(
                (New-SyntheticMobileSetting -Name 'AllowNonProvisionableDevices' -Type 'Boolean' -Value $false)
                (New-SyntheticMobileSetting)
                (New-SyntheticMobileSetting -Name 'DeviceEncryptionEnabled' -Type 'Boolean' -Value $true)
                (New-SyntheticMobileSetting -Name 'MinPasswordLength' -Type 'Int32' -Value 8)
            )
            Authority = $script:SyntheticAuthority
        }
    }

    function New-SyntheticMobileBinding {
        param(
            [string]$MailboxIdentity = 'alex.wilber@contoso.example',
            [string]$RecipientTypeDetails = 'UserMailbox',
            [string]$PolicyIdentity = 'Synthetic-Managed-Mobile-Policy'
        )
        [pscustomobject][ordered]@{
            MailboxIdentity = $MailboxIdentity
            RecipientTypeDetails = $RecipientTypeDetails
            ActiveSyncEnabled = $true
            PolicyIdentity = $PolicyIdentity
            Authority = $script:SyntheticAuthority
        }
    }

    function New-SyntheticBindingDecision {
        param(
            [string]$MailboxIdentity = 'alex.wilber@contoso.example',
            [string]$Disposition = 'ManageBinding',
            [AllowNull()]$PolicyIdentity = 'Synthetic-Managed-Mobile-Policy'
        )
        [pscustomobject][ordered]@{
            MailboxIdentity = $MailboxIdentity
            Disposition = $Disposition
            PolicyIdentity = $PolicyIdentity
            ImpactAssessment = 'Synthetic offline Exchange policy assessment only'
            ExternalDeviceOwnerEvidence = 'Unverified'
            Authority = $script:SyntheticAuthority
        }
    }

    function New-SyntheticMobileFixture {
        $policies = @((New-SyntheticMobilePolicy))
        $bindings = @((New-SyntheticMobileBinding))
        $approvedPolicies = @(
            [pscustomobject][ordered]@{
                Identity = $policies[0].Identity
                Settings = @(Copy-SyntheticMobileSettings -Settings $policies[0].Settings)
                Authority = $script:SyntheticAuthority
            }
        )
        $bindingDecisions = @((New-SyntheticBindingDecision))
        [pscustomobject][ordered]@{
            Policies = $policies
            Bindings = $bindings
            ApprovedPolicies = $approvedPolicies
            BindingDecisions = $bindingDecisions
            PolicyReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($policies); Complete = $true; NextLink = $null; Authority = 'SyntheticNonAuthoritativeFixture' }
            }.GetNewClosure()
            BindingReader = {
                param($NextLink)
                [pscustomobject][ordered]@{ Items = @($bindings); Complete = $true; NextLink = $null; Authority = 'SyntheticNonAuthoritativeFixture' }
            }.GetNewClosure()
        }
    }

    function Invoke-SyntheticMobileEvidence {
        param([Parameter(Mandatory)][object]$Fixture)
        Get-ExchangeMobileDeviceMailboxPolicyEvidence -PolicyReader $Fixture.PolicyReader `
            -MailboxBindingReader $Fixture.BindingReader -ApprovedPolicyInput $Fixture.ApprovedPolicies `
            -MailboxBindingInput $Fixture.BindingDecisions
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A08-T02 complete paged mobile-device mailbox policy evidence' {
    Context 'Negative: collection and paging boundaries' {
        It '01 rejects policy collection failure without presenting partial evidence' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.PolicyReader = { param($NextLink) throw 'SyntheticPolicyReadFailure' }
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.Complete | Should -Not -BeTrue
            $actual.FailureReason | Should -BeLike 'PolicyCollectionFailed:*SyntheticPolicyReadFailure*'
        }

        It '02 rejects mailbox-binding collection failure without presenting partial evidence' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.BindingReader = { param($NextLink) throw 'SyntheticBindingReadFailure' }
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.Complete | Should -Not -BeTrue
            $actual.FailureReason | Should -BeLike 'MailboxBindingCollectionFailed:*SyntheticBindingReadFailure*'
        }

        It '03 rejects an incomplete policy page without a continuation token' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.PolicyReader = { param($NextLink) [pscustomobject]@{ Items = @(); Complete = $false; NextLink = $null; Authority = 'SyntheticNonAuthoritativeFixture' } }
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.Complete | Should -Not -BeTrue
            $actual.FailureReason | Should -BeExactly 'PolicyCollectionIncomplete'
        }

        It '04 rejects a repeated policy continuation token' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.PolicyReader = { param($NextLink) [pscustomobject]@{ Items = @(); Complete = $false; NextLink = 'synthetic:policy:cycle'; Authority = 'SyntheticNonAuthoritativeFixture' } }
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.Complete | Should -Not -BeTrue
            $actual.FailureReason | Should -BeExactly 'PolicyPagingCycle'
        }

        It '05 rejects an incomplete mailbox-binding page without a continuation token' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.BindingReader = { param($NextLink) [pscustomobject]@{ Items = @(); Complete = $false; NextLink = $null; Authority = 'SyntheticNonAuthoritativeFixture' } }
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.Complete | Should -Not -BeTrue
            $actual.FailureReason | Should -BeExactly 'MailboxBindingCollectionIncomplete'
        }

        It '06 rejects a repeated mailbox-binding continuation token' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.BindingReader = { param($NextLink) [pscustomobject]@{ Items = @(); Complete = $false; NextLink = 'synthetic:binding:cycle'; Authority = 'SyntheticNonAuthoritativeFixture' } }
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.Complete | Should -Not -BeTrue
            $actual.FailureReason | Should -BeExactly 'MailboxBindingPagingCycle'
        }
    }

    Context 'Negative: closed typed policy input' {
        It '07 rejects a discovered policy without Identity' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.Policies[0].PSObject.Properties.Remove('Identity')
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'PolicySchemaInvalid:Identity'
        }

        It '08 rejects a discovered policy without Settings' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.Policies[0].PSObject.Properties.Remove('Settings')
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'PolicySchemaInvalid:Settings'
        }

        It '09 rejects a malformed policy page without an Items collection' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.PolicyReader = { param($NextLink) [pscustomobject]@{ Complete = $true; NextLink = $null; Authority = 'SyntheticNonAuthoritativeFixture' } }
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.Complete | Should -Not -BeTrue
            $actual.FailureReason | Should -BeExactly 'PolicyPageMalformed'
        }

        It '10 rejects a Boolean policy operand represented as text' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.ApprovedPolicies[0].Settings = @(
                Copy-SyntheticMobileSettings -Settings $fixture.Policies[0].Settings
            )
            ($fixture.ApprovedPolicies[0].Settings | Where-Object Name -CEQ 'AlphanumericPasswordRequired').Value = 'true'
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'ApprovedSettingTypeInvalid:AlphanumericPasswordRequired:Boolean'
        }

        It '11 rejects an Int32 policy operand represented as text' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.ApprovedPolicies[0].Settings = @(
                Copy-SyntheticMobileSettings -Settings $fixture.Policies[0].Settings
            )
            ($fixture.ApprovedPolicies[0].Settings | Where-Object Name -CEQ 'MinPasswordLength').Value = '8'
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'ApprovedSettingTypeInvalid:MinPasswordLength:Int32'
        }

        It '12 rejects duplicate discovered policy identities case-insensitively' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.Policies += New-SyntheticMobilePolicy -Identity 'synthetic-managed-mobile-policy'
            $discoveredPolicies = @($fixture.Policies)
            $fixture.PolicyReader = {
                param($NextLink)
                [pscustomobject][ordered]@{
                    Items = @($discoveredPolicies)
                    Complete = $true
                    NextLink = $null
                    Authority = 'SyntheticNonAuthoritativeFixture'
                }
            }.GetNewClosure()
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'PolicyIdentityDuplicate:Synthetic-Managed-Mobile-Policy'
        }
    }

    Context 'Negative: explicit binding evidence and disposition semantics' {
        It '13 rejects a discovered binding without MailboxIdentity' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.Bindings[0].PSObject.Properties.Remove('MailboxIdentity')
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'MailboxBindingSchemaInvalid:MailboxIdentity'
        }

        It '14 rejects a discovered binding without its effective PolicyIdentity' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.Bindings[0].PSObject.Properties.Remove('PolicyIdentity')
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'MailboxBindingSchemaInvalid:PolicyIdentity'
        }

        It '15 rejects duplicate discovered mailbox identities case-insensitively' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.Bindings += New-SyntheticMobileBinding -MailboxIdentity 'ALEX.WILBER@contoso.example'
            $discoveredBindings = @($fixture.Bindings)
            $fixture.BindingReader = {
                param($NextLink)
                [pscustomobject][ordered]@{
                    Items = @($discoveredBindings)
                    Complete = $true
                    NextLink = $null
                    Authority = 'SyntheticNonAuthoritativeFixture'
                }
            }.GetNewClosure()
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'MailboxBindingIdentityDuplicate:alex.wilber@contoso.example'
        }

        It '16 rejects a declared mailbox absent from complete binding evidence' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.BindingDecisions[0].MailboxIdentity = 'missing.mailbox@contoso.example'
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'DeclaredBindingEvidenceMissing:missing.mailbox@contoso.example'
        }

        It '17 rejects a disposition outside ManageBinding PreserveBinding and Exclude' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.BindingDecisions[0].Disposition = 'ImplicitDefault'
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'BindingDispositionInvalid:ImplicitDefault'
        }

        It '18 rejects ManageBinding with a non-null target outside the approved policy set' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $unapprovedPolicy = New-SyntheticMobilePolicy -Identity 'Synthetic-Unapproved-Mobile-Policy'
            $discoveredPolicies = @(
                $fixture.Policies[0]
                $unapprovedPolicy
            )
            $fixture.PolicyReader = {
                param($NextLink)
                [pscustomobject][ordered]@{
                    Items = @($discoveredPolicies)
                    Complete = $true
                    NextLink = $null
                    Authority = 'SyntheticNonAuthoritativeFixture'
                }
            }.GetNewClosure()
            $fixture.BindingDecisions[0].PolicyIdentity = $unapprovedPolicy.Identity
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'ManageBindingPolicyNotApproved:alex.wilber@contoso.example:Synthetic-Unapproved-Mobile-Policy'
        }

        It '19 rejects inconsistent mailbox-binding paging marked complete with a continuation token' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.BindingReader = { param($NextLink) [pscustomobject]@{ Items = @(); Complete = $true; NextLink = 'synthetic:binding:unexpected'; Authority = 'SyntheticNonAuthoritativeFixture' } }
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.Complete | Should -Not -BeTrue
            $actual.FailureReason | Should -BeExactly 'MailboxBindingPagingInconsistent'
        }

        It '20 rejects Exclude when a replacement target is supplied' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $fixture.BindingDecisions[0].Disposition = 'Exclude'
            $fixture.BindingDecisions[0].PolicyIdentity = 'Synthetic-Managed-Mobile-Policy'
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeFalse
            $actual.FailureReason | Should -BeExactly 'ExcludeBindingTargetForbidden:alex.wilber@contoso.example'
        }
    }

    Context 'Positive: complete synthetic non-authoritative evidence' {
        It '21 records complete pages and explicit binding decisions without claiming device controls' {
            # Arrange
            $fixture = New-SyntheticMobileFixture
            $secondPolicy = New-SyntheticMobilePolicy -Identity 'Synthetic-Preserved-Mobile-Policy'
            $preserved = New-SyntheticMobileBinding -MailboxIdentity 'shared.operations@contoso.example' -RecipientTypeDetails 'SharedMailbox' -PolicyIdentity $secondPolicy.Identity
            $excluded = New-SyntheticMobileBinding -MailboxIdentity 'room@contoso.example' -RecipientTypeDetails 'RoomMailbox' -PolicyIdentity $secondPolicy.Identity
            $fixture.ApprovedPolicies += [pscustomobject][ordered]@{
                Identity = $secondPolicy.Identity
                Settings = @(Copy-SyntheticMobileSettings -Settings $secondPolicy.Settings)
                Authority = $script:SyntheticAuthority
            }
            $fixture.BindingDecisions = @(
                (New-SyntheticBindingDecision)
                (New-SyntheticBindingDecision -MailboxIdentity $preserved.MailboxIdentity -Disposition 'PreserveBinding' -PolicyIdentity $null)
                (New-SyntheticBindingDecision -MailboxIdentity $excluded.MailboxIdentity -Disposition 'Exclude' -PolicyIdentity $null)
            )
            $fixture.PolicyReader = {
                param($NextLink)
                if ($null -eq $NextLink) { return [pscustomobject]@{ Items = @($fixture.Policies[0]); Complete = $false; NextLink = 'synthetic:policy:2'; Authority = 'SyntheticNonAuthoritativeFixture' } }
                [pscustomobject]@{ Items = @($secondPolicy); Complete = $true; NextLink = $null; Authority = 'SyntheticNonAuthoritativeFixture' }
            }.GetNewClosure()
            $fixture.BindingReader = {
                param($NextLink)
                if ($null -eq $NextLink) { return [pscustomobject]@{ Items = @($fixture.Bindings[0], $preserved); Complete = $false; NextLink = 'synthetic:binding:2'; Authority = 'SyntheticNonAuthoritativeFixture' } }
                [pscustomobject]@{ Items = @($excluded); Complete = $true; NextLink = $null; Authority = 'SyntheticNonAuthoritativeFixture' }
            }.GetNewClosure()
            # Act
            $actual = Invoke-SyntheticMobileEvidence -Fixture $fixture
            # Assert
            $actual.Collected | Should -BeTrue
            $actual.Complete | Should -BeTrue
            @($actual.Policies).Count | Should -Be 2
            @($actual.ApprovedPolicies).Count | Should -Be 2
            @($actual.MailboxBindings).Count | Should -Be 3
            @($actual.BindingDecisions).Count | Should -Be 3
            @($actual.Policies.Identity) | Should -Be @(
                'Synthetic-Managed-Mobile-Policy'
                'Synthetic-Preserved-Mobile-Policy'
            )
            @($actual.Policies | ForEach-Object {
                "$($_.Identity)|$(@($_.Settings).Count)"
            }) | Should -Be @(
                'Synthetic-Managed-Mobile-Policy|4'
                'Synthetic-Preserved-Mobile-Policy|4'
            )
            @($actual.ApprovedPolicies.Identity) | Should -Be @(
                'Synthetic-Managed-Mobile-Policy'
                'Synthetic-Preserved-Mobile-Policy'
            )
            @($actual.ApprovedPolicies | ForEach-Object {
                "$($_.Identity)|$(@($_.Settings).Count)"
            }) | Should -Be @(
                'Synthetic-Managed-Mobile-Policy|4'
                'Synthetic-Preserved-Mobile-Policy|4'
            )
            @($actual.MailboxBindings.MailboxIdentity) | Should -Be @(
                'alex.wilber@contoso.example'
                'shared.operations@contoso.example'
                'room@contoso.example'
            )
            @($actual.BindingDecisions.MailboxIdentity) | Should -Be @(
                'alex.wilber@contoso.example'
                'shared.operations@contoso.example'
                'room@contoso.example'
            )
            @($actual.Policies | ForEach-Object {
                @($_.PSObject.Properties.Name) -join '|'
            } | Select-Object -Unique) | Should -Be @('Identity|IsDefault|Settings|Authority')
            @($actual.ApprovedPolicies | ForEach-Object {
                @($_.PSObject.Properties.Name) -join '|'
            } | Select-Object -Unique) | Should -Be @('Identity|Settings|Authority')
            @($actual.MailboxBindings | ForEach-Object {
                @($_.PSObject.Properties.Name) -join '|'
            } | Select-Object -Unique) |
                Should -Be @('MailboxIdentity|RecipientTypeDetails|ActiveSyncEnabled|PolicyIdentity|Authority')
            @($actual.BindingDecisions | ForEach-Object {
                @($_.PSObject.Properties.Name) -join '|'
            } | Select-Object -Unique) |
                Should -Be @('MailboxIdentity|Disposition|PolicyIdentity|ImpactAssessment|ExternalDeviceOwnerEvidence|Authority')
            @($actual.BindingDecisions.Disposition) | Should -Be @('ManageBinding', 'PreserveBinding', 'Exclude')
            @($actual.BindingDecisions | ForEach-Object { "$($_.MailboxIdentity)|$($_.Disposition)" }) | Should -Be @(
                'alex.wilber@contoso.example|ManageBinding'
                'shared.operations@contoso.example|PreserveBinding'
                'room@contoso.example|Exclude'
            )
            @($actual.BindingDecisions | ForEach-Object {
                "$($_.MailboxIdentity)|$($_.Disposition)|$($_.PolicyIdentity)|$($_.ImpactAssessment)|$($_.ExternalDeviceOwnerEvidence)|$($_.Authority)"
            }) | Should -Be @(
                'alex.wilber@contoso.example|ManageBinding|Synthetic-Managed-Mobile-Policy|Synthetic offline Exchange policy assessment only|Unverified|SyntheticNonAuthoritativeFixture'
                'shared.operations@contoso.example|PreserveBinding||Synthetic offline Exchange policy assessment only|Unverified|SyntheticNonAuthoritativeFixture'
                'room@contoso.example|Exclude||Synthetic offline Exchange policy assessment only|Unverified|SyntheticNonAuthoritativeFixture'
            )
            ($actual.BindingDecisions | Where-Object MailboxIdentity -EQ 'alex.wilber@contoso.example').PolicyIdentity |
                Should -BeExactly 'Synthetic-Managed-Mobile-Policy'
            @($actual.BindingDecisions.ImpactAssessment | Select-Object -Unique) |
                Should -Be @('Synthetic offline Exchange policy assessment only')
            @($actual.BindingDecisions.ExternalDeviceOwnerEvidence | Select-Object -Unique) |
                Should -Be @('Unverified')
            @($actual.Policies.Settings.Name | Select-Object -Unique) | Should -Be @(
                'AllowNonProvisionableDevices'
                'AlphanumericPasswordRequired'
                'DeviceEncryptionEnabled'
                'MinPasswordLength'
            )
            @($actual.Policies.Settings | ForEach-Object {
                @($_.PSObject.Properties.Name) -join '|'
            } | Select-Object -Unique) | Should -Be @('Name|Type|Value|Authority')
            @($actual.Policies[0].Settings | ForEach-Object {
                $_.Value.GetType().Name
            }) | Should -Be @('Boolean', 'Boolean', 'Boolean', 'Int32')
            @($actual.Policies.Settings.Type | Select-Object -Unique) | Should -Be @('Boolean', 'Int32')
            @($actual.Policies | ForEach-Object {
                $policy = $_
                @($policy.Settings | ForEach-Object {
                    "$($policy.Identity)|$($_.Name)|$($_.Type)|$($_.Value)|$($_.Value.GetType().Name)|$($_.Authority)"
                })
            }) | Should -Be @(
                'Synthetic-Managed-Mobile-Policy|AllowNonProvisionableDevices|Boolean|False|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Managed-Mobile-Policy|AlphanumericPasswordRequired|Boolean|True|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Managed-Mobile-Policy|DeviceEncryptionEnabled|Boolean|True|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Managed-Mobile-Policy|MinPasswordLength|Int32|8|Int32|SyntheticNonAuthoritativeFixture'
                'Synthetic-Preserved-Mobile-Policy|AllowNonProvisionableDevices|Boolean|False|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Preserved-Mobile-Policy|AlphanumericPasswordRequired|Boolean|True|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Preserved-Mobile-Policy|DeviceEncryptionEnabled|Boolean|True|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Preserved-Mobile-Policy|MinPasswordLength|Int32|8|Int32|SyntheticNonAuthoritativeFixture'
            )
            @($actual.ApprovedPolicies.Settings.Name | Select-Object -Unique) | Should -Be @(
                'AllowNonProvisionableDevices'
                'AlphanumericPasswordRequired'
                'DeviceEncryptionEnabled'
                'MinPasswordLength'
            )
            @($actual.ApprovedPolicies.Settings | ForEach-Object {
                @($_.PSObject.Properties.Name) -join '|'
            } | Select-Object -Unique) | Should -Be @('Name|Type|Value|Authority')
            @($actual.ApprovedPolicies[0].Settings | ForEach-Object {
                $_.Value.GetType().Name
            }) | Should -Be @('Boolean', 'Boolean', 'Boolean', 'Int32')
            @($actual.ApprovedPolicies.Settings.Type | Select-Object -Unique) | Should -Be @('Boolean', 'Int32')
            @($actual.ApprovedPolicies | ForEach-Object {
                $policy = $_
                @($policy.Settings | ForEach-Object {
                    "$($policy.Identity)|$($_.Name)|$($_.Type)|$($_.Value)|$($_.Value.GetType().Name)|$($_.Authority)"
                })
            }) | Should -Be @(
                'Synthetic-Managed-Mobile-Policy|AllowNonProvisionableDevices|Boolean|False|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Managed-Mobile-Policy|AlphanumericPasswordRequired|Boolean|True|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Managed-Mobile-Policy|DeviceEncryptionEnabled|Boolean|True|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Managed-Mobile-Policy|MinPasswordLength|Int32|8|Int32|SyntheticNonAuthoritativeFixture'
                'Synthetic-Preserved-Mobile-Policy|AllowNonProvisionableDevices|Boolean|False|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Preserved-Mobile-Policy|AlphanumericPasswordRequired|Boolean|True|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Preserved-Mobile-Policy|DeviceEncryptionEnabled|Boolean|True|Boolean|SyntheticNonAuthoritativeFixture'
                'Synthetic-Preserved-Mobile-Policy|MinPasswordLength|Int32|8|Int32|SyntheticNonAuthoritativeFixture'
            )
            @($actual.Policies | ForEach-Object { "$($_.Identity)|$($_.Authority)" }) | Should -Be @(
                'Synthetic-Managed-Mobile-Policy|SyntheticNonAuthoritativeFixture'
                'Synthetic-Preserved-Mobile-Policy|SyntheticNonAuthoritativeFixture'
            )
            @($actual.ApprovedPolicies | ForEach-Object { "$($_.Identity)|$($_.Authority)" }) | Should -Be @(
                'Synthetic-Managed-Mobile-Policy|SyntheticNonAuthoritativeFixture'
                'Synthetic-Preserved-Mobile-Policy|SyntheticNonAuthoritativeFixture'
            )
            @($actual.MailboxBindings | ForEach-Object {
                "$($_.MailboxIdentity)|$($_.RecipientTypeDetails)|$($_.ActiveSyncEnabled)|$($_.PolicyIdentity)|$($_.Authority)"
            }) | Should -Be @(
                'alex.wilber@contoso.example|UserMailbox|True|Synthetic-Managed-Mobile-Policy|SyntheticNonAuthoritativeFixture'
                'shared.operations@contoso.example|SharedMailbox|True|Synthetic-Preserved-Mobile-Policy|SyntheticNonAuthoritativeFixture'
                'room@contoso.example|RoomMailbox|True|Synthetic-Preserved-Mobile-Policy|SyntheticNonAuthoritativeFixture'
            )
            @($actual.Policies.Authority | Select-Object -Unique) | Should -Be @($script:SyntheticAuthority)
            @($actual.ApprovedPolicies.Authority | Select-Object -Unique) | Should -Be @($script:SyntheticAuthority)
            @($actual.MailboxBindings.Authority | Select-Object -Unique) | Should -Be @($script:SyntheticAuthority)
            @($actual.BindingDecisions.Authority | Select-Object -Unique) | Should -Be @($script:SyntheticAuthority)
            $actual.ActualDeviceBehavior | Should -BeExactly 'Unverified'
            $actual.MobileDeviceManagement | Should -BeExactly 'Unverified'
            $actual.ConditionalAccess | Should -BeExactly 'Unverified'
            $actual.Authoritative | Should -BeFalse
        }
    }
}
