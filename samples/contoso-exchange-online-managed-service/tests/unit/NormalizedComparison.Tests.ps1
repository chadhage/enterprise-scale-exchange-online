#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    # DES-002 declares Group and Identity as resolved kinds, so the comparison needs a resolver
    # that stands in for the tenant lookup an evidence collector would perform.
    $script:Resolver = {
        param($Value)

        if ($Value -like '*@*') { return $Value }
        if ($Value -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $Value }
        if ($Value -match 'Priority Users') { return 'priority-users@contoso.example' }
        if ($Value -match 'SecOps') { return '00000000-1111-2222-3333-444444444444' }

        return $Value
    }

    $script:KindVariant = @{
        SmtpAddress = @{
            Desired = @('secops@contoso.example', 'Ops@Contoso.Example')
            Actual  = @('SMTP:Ops@contoso.example', ' secops@CONTOSO.example ', '', 'smtp:secops@contoso.example')
        }
        Domain      = @{
            Desired = @('contoso.example', 'mail.contoso.example')
            Actual  = @('MAIL.contoso.example.', ' contoso.example. ', '', 'contoso.example')
        }
        Group       = @{
            Desired = @('priority-users@contoso.example')
            Actual  = @(' Priority Users ', 'PRIORITY-USERS@contoso.example')
        }
        IpAddress   = @{
            Desired = @('203.0.113.10/32', '2001:db8::1/128')
            Actual  = @(' 2001:0DB8:0000:0000:0000:0000:0000:0001 ', '203.0.113.10', '', '203.0.113.10')
        }
        Identity    = @{
            Desired = @('00000000-1111-2222-3333-444444444444')
            Actual  = @(' Contoso\SecOps ', '00000000-1111-2222-3333-444444444444')
        }
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-005-A1 normalized collection comparison' {

    Context 'Negative: the comparison must refuse input it cannot normalize' {

        It 'fails with UnknownCanonicalKind when the kind is not declared by the comparison contract' {
            # Arrange
            $undeclaredKind = 'MailboxPlan'

            # Act
            $act = { Compare-NormalizedCollection -Desired @('contoso.example') -Actual @('contoso.example') -Kind $undeclaredKind }

            # Assert
            $act | Should -Throw -ExpectedMessage '*UnknownCanonicalKind*'
        }

        It 'fails with CollectionNotProvided when the desired collection is null' {
            # Arrange
            $missingDesired = $null

            # Act
            $act = { Compare-NormalizedCollection -Desired $missingDesired -Actual @('contoso.example') -Kind 'Domain' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CollectionNotProvided*'
        }

        It 'fails with CollectionNotProvided when the actual collection is null' {
            # Arrange
            $missingActual = $null

            # Act
            $act = { Compare-NormalizedCollection -Desired @('contoso.example') -Actual $missingActual -Kind 'Domain' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*CollectionNotProvided*'
        }

        It 'fails with NonStringCollectionMember when the desired collection carries a non-string member' {
            # Arrange
            $desired = @('contoso.example', 42)

            # Act
            $act = { Compare-NormalizedCollection -Desired $desired -Actual @('contoso.example') -Kind 'Domain' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*NonStringCollectionMember*'
        }

        It 'fails with NonStringCollectionMember when the actual collection carries a non-string member' {
            # Arrange
            $actual = @('contoso.example', [pscustomobject]@{ name = 'contoso.example' })

            # Act
            $act = { Compare-NormalizedCollection -Desired @('contoso.example') -Actual $actual -Kind 'Domain' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*NonStringCollectionMember*'
        }

        It 'fails with ResolverRequired when a group comparison is given no resolver' {
            # Arrange
            $group = @('priority-users@contoso.example')

            # Act
            $act = { Compare-NormalizedCollection -Desired $group -Actual $group -Kind 'Group' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ResolverRequired*'
        }

        It 'fails with ResolverRequired when an identity comparison is given no resolver' {
            # Arrange
            $identity = @('00000000-1111-2222-3333-444444444444')

            # Act
            $act = { Compare-NormalizedCollection -Desired $identity -Actual $identity -Kind 'Identity' }

            # Assert
            $act | Should -Throw -ExpectedMessage '*ResolverRequired*'
        }

        It 'fails with UnresolvedCanonicalValue when the resolver returns a value that is not a string' {
            # Arrange
            $brokenResolver = { param($Value) return [pscustomobject]@{ Value = $Value } }

            # Act
            $act = { Compare-NormalizedCollection -Desired @('priority-users@contoso.example') -Actual @('priority-users@contoso.example') -Kind 'Group' -Resolver $brokenResolver }

            # Assert
            $act | Should -Throw -ExpectedMessage '*UnresolvedCanonicalValue*'
        }
    }

    Context 'Negative: the comparison must report drift as drift' {

        It 'reports inequality when a desired member is absent from the actual collection' {
            # Arrange
            $desired = @('contoso.example', 'mail.contoso.example')

            # Act
            $comparison = Compare-NormalizedCollection -Desired $desired -Actual @('contoso.example') -Kind 'Domain'

            # Assert
            $comparison.Equal | Should -BeFalse
        }

        It 'reports inequality when the actual collection carries a member the desired collection does not' {
            # Arrange
            $actual = @('contoso.example', 'attacker.example')

            # Act
            $comparison = Compare-NormalizedCollection -Desired @('contoso.example') -Actual $actual -Kind 'Domain'

            # Assert
            $comparison.Equal | Should -BeFalse
        }

        It 'names the missing member when a desired member is absent from the actual collection' {
            # Arrange
            $desired = @('contoso.example', 'MAIL.contoso.example.')

            # Act
            $comparison = Compare-NormalizedCollection -Desired $desired -Actual @('contoso.example') -Kind 'Domain'

            # Assert
            $comparison.Missing | Should -Be @('mail.contoso.example')
        }

        It 'names the surplus member when the actual collection carries a member the desired collection does not' {
            # Arrange
            $actual = @('contoso.example', ' ATTACKER.example. ')

            # Act
            $comparison = Compare-NormalizedCollection -Desired @('contoso.example') -Actual $actual -Kind 'Domain'

            # Assert
            $comparison.Surplus | Should -Be @('attacker.example')
        }
    }

    Context 'Positive: formatting differences are never drift' {

        It 'reports every declared canonical kind equal when the collections differ only by formatting' {
            # Arrange
            $kind = @((Get-CanonicalComparisonContract).Kind.Kind | Sort-Object)

            # Act
            $outcome = @(
                foreach ($name in $kind) {
                    $comparison = Compare-NormalizedCollection -Desired $script:KindVariant[$name].Desired -Actual $script:KindVariant[$name].Actual -Kind $name -Resolver $script:Resolver
                    '{0}={1}:{2}:{3}' -f $name, $comparison.Equal, @($comparison.Missing).Count, @($comparison.Surplus).Count
                }
            ) -join ';'

            # Assert
            $outcome | Should -BeExactly 'Domain=True:0:0;Group=True:0:0;Identity=True:0:0;IpAddress=True:0:0;SmtpAddress=True:0:0'
        }
    }
}
