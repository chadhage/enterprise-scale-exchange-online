BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $script:SampleRoot 'scripts/ExchangeOnlineBaseline.Common.psd1') -Force
    $script:Now = [datetimeoffset]'2026-09-25T12:00:00Z'

    function New-EwsConsumerReadinessFixture {
        @{
            ConsumerInventory = @(
                @{
                    ConsumerId = 'archive-connector'
                    ApplicationId = '11111111-2222-3333-4444-555555555555'
                    UserAgent = 'ApprovedArchiver/1.0'
                    Mailboxes = @('archive@example.test')
                    Cloud = 'Worldwide'
                    Owner = 'Application owner'
                    AttestedAt = '2026-09-20T12:00:00Z'
                    MigrationOwner = 'Migration owner'
                    MigrationDate = '2026-09-30'
                    ExceptionId = 'CHG-003'
                }
            )
            ApprovedExceptions = @(
                @{
                    ExceptionId = 'CHG-003'
                    ConsumerId = 'archive-connector'
                    Cloud = 'Worldwide'
                    Owner = 'Exchange service owner'
                    ApprovedAt = '2026-09-20T12:00:00Z'
                    ExpiresAt = '2026-12-01T00:00:00Z'
                }
            )
            MailboxReadback = @(
                @{
                    Identity = 'archive@example.test'
                    EwsEnabled = $null
                    EwsApplicationAccessPolicy = $null
                    EwsAllowList = @()
                }
            )
            RetirementNotices = @(
                @{
                    Cloud = 'Worldwide'
                    ReviewedAt = '2026-09-21T00:00:00Z'
                    ReviewRequiredBefore = '2026-10-01T00:00:00Z'
                    ExceptionSupportedUntil = '2027-04-01T00:00:00Z'
                }
            )
        }
    }
}

Describe 'EXR-007-A01 EWS consumer and migration readiness reconciliation' {
    Context 'Negative: incomplete or unbound supplied readiness evidence' {
        It 'refuses a missing EWS consumer inventory' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.ConsumerInventory = @()

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsConsumerInventoryMissing'
        }

        It 'refuses a consumer without an accountable owner' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.ConsumerInventory[0].Owner = ''

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsConsumerOwnerMissing:archive-connector'
        }

        It 'refuses a consumer without a migration owner and date' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.ConsumerInventory[0].MigrationOwner = ''
            $fixture.ConsumerInventory[0].MigrationDate = $null

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsMigrationPlanMissing:archive-connector'
        }

        It 'refuses a stale consumer attestation' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.ConsumerInventory[0].AttestedAt = '2026-08-01T00:00:00Z'

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsConsumerAttestationStale:archive-connector'
        }

        It 'refuses a consumer attested for a different cloud' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.ConsumerInventory[0].Cloud = 'GCC'

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsConsumerCloudMismatch:archive-connector'
        }

        It 'refuses an exception that does not match a declared consumer' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.ApprovedExceptions[0].ConsumerId = 'undeclared-consumer'

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsConsumerExceptionUnmatched:CHG-003'
        }

        It 'refuses an exception beyond the cloud retirement boundary' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.ApprovedExceptions[0].ExpiresAt = '2027-04-02T00:00:00Z'

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsConsumerExceptionBeyondRetirement:CHG-003'
        }

        It 'refuses a consumer without its declared approved exception' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.ApprovedExceptions = @()

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsConsumerExceptionMissing:archive-connector'
        }

        It 'refuses an exception for a different cloud than its consumer' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.ApprovedExceptions[0].Cloud = 'GCC'
            $fixture.RetirementNotices += @{
                Cloud = 'GCC'
                ReviewedAt = '2026-09-21T00:00:00Z'
                ReviewRequiredBefore = '2026-10-01T00:00:00Z'
                ExceptionSupportedUntil = '2027-04-01T00:00:00Z'
            }

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsConsumerExceptionCloudMismatch:CHG-003'
        }

        It 'refuses mailbox readback beyond the declared consumer inventory' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.MailboxReadback += @{
                Identity = 'surplus@example.test'
                EwsEnabled = $null
                EwsApplicationAccessPolicy = $null
                EwsAllowList = @()
            }

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsMailboxReadbackSurplus:surplus@example.test'
        }

        It 'refuses an expired exception before the retirement boundary' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.ApprovedExceptions[0].ExpiresAt = '2026-09-24T00:00:00Z'

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsConsumerExceptionExpired:CHG-003'
        }

        It 'refuses a stale and overdue retirement notice' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture
            $fixture.RetirementNotices[0].ReviewedAt = '2026-08-01T00:00:00Z'
            $fixture.RetirementNotices[0].ReviewRequiredBefore = '2026-09-24T00:00:00Z'

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Error
            $result.Reason | Should -BeExactly 'EwsRetirementNoticeStale:Worldwide'
        }
    }

    Context 'Positive: complete supplied evidence remains distinct from external readiness' {
        It 'reconciles one approved consumer and exception with independent mailbox readback' {
            # Arrange
            $fixture = New-EwsConsumerReadinessFixture

            # Act
            $result = Test-BaselineEwsConsumerReadiness @fixture -Now $script:Now

            # Assert
            $result.Status | Should -BeExactly Pass
            $result.Reason | Should -BeExactly 'EwsConsumerReadinessReconciled'
            $result.ConsumerCount | Should -Be 1
            $result.ExceptionCount | Should -Be 1
            $result.MailboxCount | Should -Be 1
            $result.ExternalMigrationReadiness | Should -BeExactly Unverified
        }
    }
}