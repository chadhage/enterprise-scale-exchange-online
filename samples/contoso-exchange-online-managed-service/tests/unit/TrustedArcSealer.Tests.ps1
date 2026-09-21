#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $script:SampleRoot 'scripts\ExchangeOnlineBaseline.Common.psm1') -Force -DisableNameChecking

    function New-ArcEvidence {
        param([object[]]$ArcConfig = @([pscustomobject]@{ Identity = 'Default'; ArcTrustedSealers = @('sealer.gateway.example') }))
        Get-TrustedArcSealerEvidence -ArcConfigCollection { $ArcConfig }.GetNewClosure()
    }
}

Describe 'PP-004 trusted ARC collector' {
    It 'refuses a missing ARC collection seam' {
        # Arrange
        $act = { Get-TrustedArcSealerEvidence -ArcConfigCollection $null }
        # Act / Assert
        $act | Should -Throw '*ArcConfigCollectionRequired*'
    }

    It 'records an ARC collection failure without converting it to a verdict' {
        # Arrange
        $collection = { throw 'offline throttle' }
        # Act
        $evidence = Get-TrustedArcSealerEvidence -ArcConfigCollection $collection
        # Assert
        $evidence.ControlId | Should -BeExactly 'PP-004'
        $evidence.Collected | Should -BeFalse
        $evidence.FailureReason | Should -Match 'offline throttle'
    }

    It 'keeps the whole ARC payload unchanged' {
        # Arrange
        $payload = @([pscustomobject]@{ Identity = 'Default'; ArcTrustedSealers = @('sealer.gateway.example'); Unrelated = 'preserve-me' })
        # Act
        $evidence = New-ArcEvidence -ArcConfig $payload
        # Assert
        (ConvertTo-CanonicalJson -InputObject $evidence.Value) | Should -Match '"Unrelated":"preserve-me"'
        $evidence.Command | Should -BeExactly 'Get-ArcConfig'
    }

    It 'collects one immutable PP-004 record from Get-ArcConfig' {
        # Arrange
        $payload = @([pscustomobject]@{ Identity = 'Default'; ArcTrustedSealers = @('sealer.gateway.example') })
        # Act
        $evidence = New-ArcEvidence -ArcConfig $payload
        # Assert
        $evidence.ControlId | Should -BeExactly 'PP-004'
        { $evidence.ControlId = 'OTHER' } | Should -Throw
    }
}

Describe 'PP-004 trusted ARC evaluator' {
    It 'returns Error when ARC collection failed' {
        # Arrange
        $evidence = Get-TrustedArcSealerEvidence -ArcConfigCollection { throw 'denied' }
        # Act
        $result = Test-TrustedArcSealerControl -Evidence $evidence -DesiredState @('sealer.gateway.example')
        # Assert
        $result.Status | Should -BeExactly 'Error'
    }

    It 'returns Error when the ARC observation lacks ArcTrustedSealers' {
        # Arrange
        $evidence = New-ArcEvidence -ArcConfig @([pscustomobject]@{ Identity = 'Default' })
        # Act
        $result = Test-TrustedArcSealerControl -Evidence $evidence -DesiredState @('sealer.gateway.example')
        # Assert
        $result.Status | Should -BeExactly 'Error'
    }

    It 'attributes a missing trusted sealer to PP-004' {
        # Arrange
        $evidence = New-ArcEvidence -ArcConfig @([pscustomobject]@{ Identity = 'Default'; ArcTrustedSealers = @() })
        # Act
        $result = Test-TrustedArcSealerControl -Evidence $evidence -DesiredState @('sealer.gateway.example')
        # Assert
        $result.ControlId | Should -BeExactly 'PP-004'
        $result.Status | Should -BeExactly 'Fail'
        $result.Reason | Should -Match 'sealer.gateway.example'
    }

    It 'attributes a surplus trusted sealer to PP-004' {
        # Arrange
        $evidence = New-ArcEvidence -ArcConfig @([pscustomobject]@{ Identity = 'Default'; ArcTrustedSealers = @('sealer.gateway.example', 'surplus.example') })
        # Act
        $result = Test-TrustedArcSealerControl -Evidence $evidence -DesiredState @('sealer.gateway.example')
        # Assert
        $result.ControlId | Should -BeExactly 'PP-004'
        $result.Status | Should -BeExactly 'Fail'
        $result.Reason | Should -Match 'surplus.example'
    }

    It 'passes one exact normalized trusted-sealer set' {
        # Arrange
        $evidence = New-ArcEvidence -ArcConfig @([pscustomobject]@{ Identity = 'Default'; ArcTrustedSealers = @(' SEALER.GATEWAY.EXAMPLE. ') })
        # Act
        $result = Test-TrustedArcSealerControl -Evidence $evidence -DesiredState @('sealer.gateway.example')
        # Assert
        $result.ControlId | Should -BeExactly 'PP-004'
        $result.Status | Should -BeExactly 'Pass'
        $result.GoLiveSuccess | Should -BeTrue
    }
}