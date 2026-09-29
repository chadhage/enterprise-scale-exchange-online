#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonManifestPath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psd1'
    Import-Module -Name $script:CommonManifestPath -Force -DisableNameChecking -ErrorAction Stop

    function Copy-OwaEvidenceFixture {
        param([Parameter(Mandatory)][object]$InputObject)

        $InputObject | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20
    }

    function New-OwaPolicy {
        param(
            [string]$Identity = 'OWA-Approved',
            [object]$DirectFileAccessOnPublicComputersEnabled = $false,
            [object]$DirectFileAccessOnPrivateComputersEnabled = $false,
            [object]$WacViewingOnPublicComputersEnabled = $true,
            [object]$WacViewingOnPrivateComputersEnabled = $true,
            [bool]$Approved = $true
        )

        [pscustomobject][ordered]@{
            Identity = $Identity
            IsDefault = $Identity -eq 'OWA-Approved'
            Approved = $Approved
            DirectFileAccessOnPublicComputersEnabled = $DirectFileAccessOnPublicComputersEnabled
            DirectFileAccessOnPrivateComputersEnabled = $DirectFileAccessOnPrivateComputersEnabled
            WacViewingOnPublicComputersEnabled = $WacViewingOnPublicComputersEnabled
            WacViewingOnPrivateComputersEnabled = $WacViewingOnPrivateComputersEnabled
            EvidenceAuthority = 'SyntheticNonAuthoritative'
            IsAuthoritative = $false
        }
    }

    function New-OwaBinding {
        param(
            [string]$Mailbox = 'default',
            [string]$Policy = 'OWA-Approved',
            [string]$BindingType = 'Default',
            [bool]$Applicable = $true,
            [bool]$Authorized = $true
        )

        [pscustomobject][ordered]@{
            Mailbox = $Mailbox
            Policy = $Policy
            BindingType = $BindingType
            Applicable = $Applicable
            Authorized = $Authorized
            EvidenceOnly = $true
            Mutable = $false
            EvidenceAuthority = 'SyntheticNonAuthoritative'
            IsAuthoritative = $false
        }
    }

    function New-OwaDependencyAssessment {
        [pscustomobject][ordered]@{
            Owa = [pscustomobject]@{
                Assessed = $true
                Status = 'Unverified'
                Reference = 'fixture:dependency:owa'
            }
            NewOutlook = [pscustomobject]@{
                Assessed = $true
                Status = 'Unverified'
                Reference = 'fixture:dependency:new-outlook'
            }
            ConditionalAccess = [pscustomobject]@{
                Included = $false
                Reason = 'ExcludedFromExchangeOwaMailboxPolicyEvidence'
            }
            LiveClients = [pscustomobject]@{
                Included = $false
                Reason = 'ExcludedFromSyntheticEvidence'
            }
            EvidenceAuthority = 'SyntheticNonAuthoritative'
            IsAuthoritative = $false
        }
    }

    function New-OwaEvidenceReaders {
        param(
            [object[]]$Policies = @((New-OwaPolicy)),
            [object[]]$DefaultBindings = @((New-OwaBinding)),
            [object[]]$ExplicitBindings = @(
                (New-OwaBinding -Mailbox 'alex.wilber@contoso.example' -BindingType 'Explicit'),
                (New-OwaBinding -Mailbox 'shared.operations@contoso.example' -BindingType 'Explicit')
            ),
            [object]$Dependencies = (New-OwaDependencyAssessment)
        )

        @{
            PolicyReader = {
                [pscustomobject][ordered]@{ Items = @($Policies); Complete = $true; NextLink = $null }
            }.GetNewClosure()
            DefaultBindingReader = {
                [pscustomobject][ordered]@{ Items = @($DefaultBindings); Complete = $true; NextLink = $null }
            }.GetNewClosure()
            ExplicitBindingReader = {
                [pscustomobject][ordered]@{ Items = @($ExplicitBindings); Complete = $true; NextLink = $null }
            }.GetNewClosure()
            DependencyAssessmentReader = { $Dependencies }.GetNewClosure()
        }
    }

    function Invoke-OwaEvidenceFixture {
        param(
            [Parameter(Mandatory)][hashtable]$Readers
        )

        Get-ExchangeOwaMailboxPolicyEvidence `
            -PolicyReader $Readers.PolicyReader `
            -DefaultBindingReader $Readers.DefaultBindingReader `
            -ExplicitBindingReader $Readers.ExplicitBindingReader `
            -DependencyAssessmentReader $Readers.DependencyAssessmentReader
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'EXR-007-A08-T03 complete OWA mailbox policy and binding evidence' {
    Context 'Negative: independent collection and raw-read completeness' {
        It '01 rejects an OWA mailbox policy collection failure' {
            # Arrange
            $readers = New-OwaEvidenceReaders
            $readers.PolicyReader = { throw 'SyntheticPolicyReadFailure' }

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeLike 'PolicyCollectionFailed:*SyntheticPolicyReadFailure*'
        }

        It '02 rejects a default-binding collection failure' {
            # Arrange
            $readers = New-OwaEvidenceReaders
            $readers.DefaultBindingReader = { throw 'SyntheticDefaultBindingReadFailure' }

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeLike 'DefaultBindingCollectionFailed:*SyntheticDefaultBindingReadFailure*'
        }

        It '03 rejects an explicit applicable-binding collection failure' {
            # Arrange
            $readers = New-OwaEvidenceReaders
            $readers.ExplicitBindingReader = { throw 'SyntheticExplicitBindingReadFailure' }

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeLike 'ExplicitBindingCollectionFailed:*SyntheticExplicitBindingReadFailure*'
        }

        It '04 rejects an incomplete OWA mailbox policy raw read' {
            # Arrange
            $readers = New-OwaEvidenceReaders
            $readers.PolicyReader = {
                [pscustomobject][ordered]@{
                    Items = @((New-OwaPolicy))
                    Complete = $false
                    NextLink = $null
                }
            }

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PolicyCollectionIncomplete'
        }

        It '05 rejects an incomplete default-binding raw read' {
            # Arrange
            $readers = New-OwaEvidenceReaders
            $readers.DefaultBindingReader = {
                [pscustomobject][ordered]@{
                    Items = @((New-OwaBinding))
                    Complete = $false
                    NextLink = $null
                }
            }

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'DefaultBindingCollectionIncomplete'
        }

        It '06 rejects an incomplete explicit applicable-binding raw read' {
            # Arrange
            $readers = New-OwaEvidenceReaders
            $readers.ExplicitBindingReader = {
                [pscustomobject][ordered]@{
                    Items = @(
                        (New-OwaBinding -Mailbox 'alex.wilber@contoso.example' -BindingType 'Explicit'),
                        (New-OwaBinding -Mailbox 'shared.operations@contoso.example' -BindingType 'Explicit')
                    )
                    Complete = $false
                    NextLink = $null
                }
            }

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'ExplicitBindingCollectionIncomplete'
        }
    }

    Context 'Negative: continuation-page integrity and identity ambiguity' {
        It '07 rejects a failed OWA mailbox policy continuation-page read' {
            # Arrange
            $readers = New-OwaEvidenceReaders
            $readers.PolicyReader = {
                param($NextLink)

                if ($null -eq $NextLink) {
                    return [pscustomobject][ordered]@{
                        Items = @((New-OwaPolicy))
                        Complete = $false
                        NextLink = 'fixture:policy:page-2'
                    }
                }

                throw 'SyntheticPolicyContinuationReadFailure'
            }

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason |
                Should -BeExactly 'PolicyCollectionFailed:SyntheticPolicyContinuationReadFailure'
        }

        It '08 rejects a malformed OWA mailbox policy continuation page' {
            # Arrange
            $readers = New-OwaEvidenceReaders
            $readers.PolicyReader = {
                param($NextLink)

                if ($null -eq $NextLink) {
                    return [pscustomobject][ordered]@{
                        Items = @((New-OwaPolicy))
                        Complete = $false
                        NextLink = 'fixture:policy:page-2'
                    }
                }

                [pscustomobject][ordered]@{
                    Complete = $true
                    NextLink = $null
                }
            }

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PolicyCollectionMalformed:Items'
        }

        It '09 rejects a duplicate normalized OWA mailbox policy identity across pages' {
            # Arrange
            $readers = New-OwaEvidenceReaders
            $readers.PolicyReader = {
                param($NextLink)

                if ($null -eq $NextLink) {
                    return [pscustomobject][ordered]@{
                        Items = @((New-OwaPolicy -Identity 'OWA-Approved'))
                        Complete = $false
                        NextLink = 'fixture:policy:page-2'
                    }
                }

                [pscustomobject][ordered]@{
                    Items = @((New-OwaPolicy -Identity ' owa-approved '))
                    Complete = $true
                    NextLink = $null
                }
            }

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PolicyIdentityAmbiguous:OWA-Approved'
        }
    }

    Context 'Negative: missing, wrong, or unauthorized bindings' {
        It '10 rejects missing default mailbox policy binding evidence' {
            # Arrange
            $readers = New-OwaEvidenceReaders -DefaultBindings @()

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'DefaultBindingMissing'
        }

        It '11 rejects a default binding to the wrong OWA mailbox policy' {
            # Arrange
            $readers = New-OwaEvidenceReaders -DefaultBindings @(
                (New-OwaBinding -Policy 'OWA-Unapproved')
            )

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'DefaultBindingPolicyMismatch:OWA-Unapproved'
        }

        It '12 rejects missing explicit bindings for applicable mailboxes' {
            # Arrange
            $readers = New-OwaEvidenceReaders -ExplicitBindings @()

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'ApplicableExplicitBindingMissing'
        }

        It '13 rejects an unauthorized applicable mailbox binding' {
            # Arrange
            $readers = New-OwaEvidenceReaders -ExplicitBindings @(
                (New-OwaBinding -Mailbox 'alex.wilber@contoso.example' -BindingType 'Explicit' -Authorized $false),
                (New-OwaBinding -Mailbox 'shared.operations@contoso.example' -BindingType 'Explicit')
            )

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'ExplicitBindingUnauthorized:alex.wilber@contoso.example'
        }

        It '14 rejects a binding to an unauthorized OWA mailbox policy' {
            # Arrange
            $readers = New-OwaEvidenceReaders -Policies @(
                (New-OwaPolicy -Approved $false)
            )

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PolicyUnauthorized:OWA-Approved'
        }
    }

    Context 'Negative: approved settings and dependency boundaries' {
        It '15 rejects an approved policy with a missing required setting' {
            # Arrange
            $policy = New-OwaPolicy
            $policy.PSObject.Properties.Remove('DirectFileAccessOnPublicComputersEnabled')
            $readers = New-OwaEvidenceReaders -Policies @($policy)

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PolicySettingMissing:DirectFileAccessOnPublicComputersEnabled'
        }

        It '16 rejects an approved policy with a wrong required setting' {
            # Arrange
            $readers = New-OwaEvidenceReaders -Policies @(
                (New-OwaPolicy -DirectFileAccessOnPrivateComputersEnabled $true)
            )

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PolicySettingMismatch:DirectFileAccessOnPrivateComputersEnabled'
        }

        It '17 rejects an unauthorized raw OWA mailbox policy setting' {
            # Arrange
            $policy = New-OwaPolicy
            $policy | Add-Member -NotePropertyName 'ConditionalAccessPolicy' -NotePropertyValue 'RequireCompliantDevice'
            $readers = New-OwaEvidenceReaders -Policies @($policy)

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'PolicySettingUnauthorized:ConditionalAccessPolicy'
        }

        It '18 rejects absent OWA dependency assessment evidence' {
            # Arrange
            $dependencies = New-OwaDependencyAssessment
            $dependencies.PSObject.Properties.Remove('Owa')
            $readers = New-OwaEvidenceReaders -Dependencies $dependencies

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'DependencyAssessmentMissing:OWA'
        }

        It '19 rejects absent new Outlook dependency assessment evidence' {
            # Arrange
            $dependencies = New-OwaDependencyAssessment
            $dependencies.PSObject.Properties.Remove('NewOutlook')
            $readers = New-OwaEvidenceReaders -Dependencies $dependencies

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'DependencyAssessmentMissing:NewOutlook'
        }

        It '20 rejects inclusion of Conditional Access in Exchange policy evidence' {
            # Arrange
            $dependencies = New-OwaDependencyAssessment
            $dependencies.ConditionalAccess.Included = $true
            $readers = New-OwaEvidenceReaders -Dependencies $dependencies

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeFalse
            $result.FailureReason | Should -BeExactly 'ConditionalAccessNotInScope'
        }
    }

    Context 'Positive: complete synthetic non-authoritative evidence' {
        It '21 records complete default and explicit bindings plus approved settings without behavior claims or mutation' {
            # Arrange
            $policies = @((New-OwaPolicy))
            $defaultBindings = @((New-OwaBinding))
            $explicitBindings = @(
                (New-OwaBinding -Mailbox 'alex.wilber@contoso.example' -BindingType 'Explicit'),
                (New-OwaBinding -Mailbox 'shared.operations@contoso.example' -BindingType 'Explicit')
            )
            $dependencies = New-OwaDependencyAssessment
            $before = @($policies, $defaultBindings, $explicitBindings, $dependencies) |
                ConvertTo-Json -Depth 20 -Compress
            $readers = New-OwaEvidenceReaders -Policies $policies `
                -DefaultBindings $defaultBindings -ExplicitBindings $explicitBindings `
                -Dependencies $dependencies

            # Act
            $result = Invoke-OwaEvidenceFixture -Readers $readers

            # Assert
            $result.Collected | Should -BeTrue
            $result.FailureReason | Should -BeNullOrEmpty
            @($result.PSObject.Properties.Name) | Should -Be @(
                'Collected',
                'FailureReason',
                'Value',
                'ActualClientBehavior',
                'AssignmentProvenance'
            )
            @($result.Value.PSObject.Properties.Name) | Should -Be @(
                'Policies',
                'DefaultBindings',
                'ExplicitBindings',
                'Dependencies',
                'EvidenceAuthority',
                'IsAuthoritative'
            )
            @($result.Value.Policies[0].PSObject.Properties.Name) | Should -Be @(
                'Identity',
                'IsDefault',
                'Approved',
                'DirectFileAccessOnPublicComputersEnabled',
                'DirectFileAccessOnPrivateComputersEnabled',
                'WacViewingOnPublicComputersEnabled',
                'WacViewingOnPrivateComputersEnabled',
                'EvidenceAuthority',
                'IsAuthoritative'
            )
            @($result.Value.DefaultBindings[0].PSObject.Properties.Name) | Should -Be @(
                'Mailbox',
                'Policy',
                'BindingType',
                'Applicable',
                'Authorized',
                'EvidenceOnly',
                'Mutable',
                'EvidenceAuthority',
                'IsAuthoritative'
            )
            @($result.Value.ExplicitBindings[0].PSObject.Properties.Name) |
                Should -Be @($result.Value.DefaultBindings[0].PSObject.Properties.Name)
            @($result.Value.Dependencies.PSObject.Properties.Name) | Should -Be @(
                'Owa',
                'NewOutlook',
                'ConditionalAccess',
                'LiveClients',
                'EvidenceAuthority',
                'IsAuthoritative'
            )
            @($result.Value.Dependencies.Owa.PSObject.Properties.Name) | Should -Be @(
                'Assessed',
                'Status',
                'Reference'
            )
            @($result.Value.Dependencies.NewOutlook.PSObject.Properties.Name) |
                Should -Be @($result.Value.Dependencies.Owa.PSObject.Properties.Name)
            @($result.Value.Dependencies.ConditionalAccess.PSObject.Properties.Name) |
                Should -Be @('Included', 'Reason')
            @($result.Value.Dependencies.LiveClients.PSObject.Properties.Name) |
                Should -Be @('Included', 'Reason')
            @($result.Value.Policies).Count | Should -Be 1
            @($result.Value.DefaultBindings).Count | Should -Be 1
            @($result.Value.ExplicitBindings).Count | Should -Be 2
            @($result.Value.DefaultBindings.Policy) | Should -Be @('OWA-Approved')
            $result.Value.DefaultBindings[0].Mailbox | Should -BeExactly 'default'
            $result.Value.DefaultBindings[0].BindingType | Should -BeExactly 'Default'
            $result.Value.DefaultBindings[0].Applicable | Should -BeTrue
            $result.Value.DefaultBindings[0].Authorized | Should -BeTrue
            @($result.Value.ExplicitBindings.Policy | Select-Object -Unique) | Should -Be @('OWA-Approved')
            @($result.Value.ExplicitBindings.Mailbox) | Should -Be @(
                'alex.wilber@contoso.example',
                'shared.operations@contoso.example'
            )
            @($result.Value.ExplicitBindings.Applicable) | Should -Be @($true, $true)
            @($result.Value.ExplicitBindings.Authorized) | Should -Be @($true, $true)
            $result.Value.Policies[0].DirectFileAccessOnPublicComputersEnabled | Should -BeFalse
            $result.Value.Policies[0].DirectFileAccessOnPrivateComputersEnabled | Should -BeFalse
            $result.Value.Policies[0].WacViewingOnPublicComputersEnabled | Should -BeTrue
            $result.Value.Policies[0].WacViewingOnPrivateComputersEnabled | Should -BeTrue
            $result.Value.Policies[0].DirectFileAccessOnPublicComputersEnabled |
                Should -BeOfType ([bool])
            $result.Value.Policies[0].DirectFileAccessOnPrivateComputersEnabled |
                Should -BeOfType ([bool])
            $result.Value.Policies[0].WacViewingOnPublicComputersEnabled |
                Should -BeOfType ([bool])
            $result.Value.Policies[0].WacViewingOnPrivateComputersEnabled |
                Should -BeOfType ([bool])
            @($result.Value.DefaultBindings + $result.Value.ExplicitBindings |
                Where-Object { -not $_.EvidenceOnly -or $_.Mutable }).Count | Should -Be 0
            $result.ActualClientBehavior | Should -BeExactly 'Unverified'
            $result.AssignmentProvenance | Should -BeExactly 'Unverified'
            $result.Value.Dependencies.Owa.Assessed | Should -BeTrue
            $result.Value.Dependencies.Owa.Status | Should -BeExactly 'Unverified'
            $result.Value.Dependencies.Owa.Reference |
                Should -BeExactly 'fixture:dependency:owa'
            $result.Value.Dependencies.NewOutlook.Assessed | Should -BeTrue
            $result.Value.Dependencies.NewOutlook.Status | Should -BeExactly 'Unverified'
            $result.Value.Dependencies.NewOutlook.Reference |
                Should -BeExactly 'fixture:dependency:new-outlook'
            $result.Value.Dependencies.ConditionalAccess.Included | Should -BeFalse
            $result.Value.Dependencies.ConditionalAccess.Reason |
                Should -BeExactly 'ExcludedFromExchangeOwaMailboxPolicyEvidence'
            $result.Value.Dependencies.LiveClients.Included | Should -BeFalse
            $result.Value.Dependencies.LiveClients.Reason |
                Should -BeExactly 'ExcludedFromSyntheticEvidence'
            $result.Value.Dependencies.EvidenceAuthority |
                Should -BeExactly 'SyntheticNonAuthoritative'
            $result.Value.Dependencies.IsAuthoritative | Should -BeFalse
            $result.Value.Policies[0].EvidenceAuthority |
                Should -BeExactly 'SyntheticNonAuthoritative'
            $result.Value.Policies[0].IsAuthoritative | Should -BeFalse
            $result.Value.DefaultBindings[0].EvidenceAuthority |
                Should -BeExactly 'SyntheticNonAuthoritative'
            $result.Value.DefaultBindings[0].IsAuthoritative | Should -BeFalse
            @($result.Value.ExplicitBindings.EvidenceAuthority) | Should -Be @(
                'SyntheticNonAuthoritative',
                'SyntheticNonAuthoritative'
            )
            @($result.Value.ExplicitBindings.IsAuthoritative) | Should -Be @($false, $false)
            $result.Value.EvidenceAuthority | Should -BeExactly 'SyntheticNonAuthoritative'
            $result.Value.IsAuthoritative | Should -BeFalse
            (@($policies, $defaultBindings, $explicitBindings, $dependencies) |
                ConvertTo-Json -Depth 20 -Compress) | Should -BeExactly $before
        }
    }
}
