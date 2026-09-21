BeforeAll {
    $sampleRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
}
Describe 'EXR-001 operator entrypoint isolation' {
    It 'does not present <Path> historical instructions as the active journey' -ForEach @(
        @{ Path = 'README.md' }
        @{ Path = 'docs/IMPLEMENTATION-GUIDE.md' }
        @{ Path = 'docs/RUNBOOKS.md' }
    ) {
        # Arrange
        $pathToRead = Join-Path $sampleRoot $Path
        # Act
        $header = Get-Content $pathToRead -TotalCount 12 | Out-String
        # Assert
        $header | Should -Match 'EXCHANGE-ONLY.md'
        $header | Should -Match 'Historical reference only'
    }
    It 'executes the documented default preview with synthetic approved inputs' {
        # Arrange
        $documentation = Get-Content (Join-Path $sampleRoot 'docs/EXCHANGE-ONLY.md') -Raw
        $example = [regex]::Match($documentation, '(?s)```powershell\s*(?<command>.*?)```').Groups['command'].Value
        $parameters = Get-Content (Join-Path $sampleRoot 'config/parameters.exchange-only.sample.json') -Raw | ConvertFrom-Json -AsHashtable
        $parameters.entitlement.verified = $true
        $parameters.entitlement.expiresOn = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
        $parameters.entitlement.servicePlans = @('EXCHANGE_S_ENTERPRISE','ATP_ENTERPRISE','THREAT_INTELLIGENCE')
        $parameterPath = Join-Path $TestDrive 'approved-offline.json'
        $parameters | ConvertTo-Json -Depth 20 | Set-Content $parameterPath
        $example = $example.Replace('./config/parameters.exchange-only.sample.json', "'$parameterPath'")
        Push-Location $sampleRoot
        try {
            # Act
            $plan = & ([scriptblock]::Create($example))
            # Assert
            $plan.Kind | Should -BeExactly 'ExchangeOnlyPlan'
            $plan.DeploymentProfile | Should -BeExactly 'ExchangeOnly'
            @($plan.ControlId).Count | Should -Be 25
            $plan.ExternalReadiness.Status | Should -BeExactly 'Unverified'
        }
        finally { Pop-Location }
    }
}