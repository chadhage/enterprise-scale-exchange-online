#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    function New-DeeplyNestedDocument {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [int]$Level
        )

        $node = [ordered]@{ leaf = 'bottom' }
        for ($index = 0; $index -lt $Level; $index++) {
            $node = [ordered]@{ child = $node }
        }

        return $node
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'COM-004-A1 canonical JSON serialization' {

    Context 'Negative: canonicalization must refuse unusable input' {

        It 'fails with CanonicalInputNotProvided when no document is supplied' {
            # Arrange
            $absentDocument = $null

            # Act
            $act = { ConvertTo-CanonicalJson -InputObject $absentDocument }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CanonicalInputNotProvided*'
        }

        It 'fails with UnsupportedCanonicalValue when a member is not JSON representable' {
            # Arrange
            $document = [ordered]@{ callback = { 'executable' } }

            # Act
            $act = { ConvertTo-CanonicalJson -InputObject $document }

            # Assert
            $act | Should -Throw -ExpectedMessage 'UnsupportedCanonicalValue*'
        }

        It 'fails with CanonicalDepthExceeded when the document nests beyond the supported depth' {
            # Arrange
            $document = New-DeeplyNestedDocument -Level 70

            # Act
            $act = { ConvertTo-CanonicalJson -InputObject $document }

            # Assert
            $act | Should -Throw -ExpectedMessage 'CanonicalDepthExceeded*'
        }
    }

    Context 'Negative: canonicalization must not emit a non-canonical form' {

        It 'does not preserve the source member order' {
            # Arrange
            $document = [ordered]@{ zulu = 1; alpha = 2; mike = 3 }

            # Act
            $canonical = ConvertTo-CanonicalJson -InputObject $document

            # Assert
            $canonical | Should -BeExactly '{"alpha":2,"mike":3,"zulu":1}'
        }

        It 'does not retain insignificant whitespace' {
            # Arrange
            $document = [ordered]@{ outer = [ordered]@{ inner = @(1, 2) } }

            # Act
            $canonical = ConvertTo-CanonicalJson -InputObject $document

            # Assert
            $canonical | Should -BeExactly '{"outer":{"inner":[1,2]}}'
        }

        It 'does not emit a byte order mark' {
            # Arrange
            $document = [ordered]@{ alpha = 1 }

            # Act
            $canonical = ConvertTo-CanonicalJson -InputObject $document

            # Assert
            $canonical.StartsWith([char]0xFEFF) | Should -BeFalse
        }

        It 'does not emit a line break' {
            # Arrange
            $document = [ordered]@{ alpha = 1; bravo = [ordered]@{ charlie = 2 } }

            # Act
            $canonical = ConvertTo-CanonicalJson -InputObject $document

            # Assert
            $canonical.Contains("`n") | Should -BeFalse
        }

        It 'does not drop a null member' {
            # Arrange
            $document = [ordered]@{ alpha = $null }

            # Act
            $canonical = ConvertTo-CanonicalJson -InputObject $document

            # Assert
            $canonical | Should -BeExactly '{"alpha":null}'
        }

        It 'does not alter a boolean member' {
            # Arrange
            $document = [ordered]@{ disabled = $false; enabled = $true }

            # Act
            $canonical = ConvertTo-CanonicalJson -InputObject $document

            # Assert
            $canonical | Should -BeExactly '{"disabled":false,"enabled":true}'
        }

        It 'does not reformat a numeric member' {
            # Arrange
            $document = [ordered]@{ count = 42; ratio = 1.5 }

            # Act
            $canonical = ConvertTo-CanonicalJson -InputObject $document

            # Assert
            $canonical | Should -BeExactly '{"count":42,"ratio":1.5}'
        }

        It 'does not escape or lose a non-ASCII string member' {
            # Arrange
            $document = [ordered]@{ owner = 'Ünïcødé' }

            # Act
            $canonical = ConvertTo-CanonicalJson -InputObject $document

            # Assert
            $canonical | Should -BeExactly '{"owner":"Ünïcødé"}'
        }

        It 'does not reorder array elements' {
            # Arrange
            $document = [ordered]@{ hops = @('second', 'first') }

            # Act
            $canonical = ConvertTo-CanonicalJson -InputObject $document

            # Assert
            $canonical | Should -BeExactly '{"hops":["second","first"]}'
        }

        It 'does not produce different text for documents that differ only in member order' {
            # Arrange
            $ascending = [ordered]@{ alpha = 1; bravo = 2; charlie = 3 }
            $descending = [ordered]@{ charlie = 3; bravo = 2; alpha = 1 }

            # Act
            $difference = Compare-Object -ReferenceObject (ConvertTo-CanonicalJson -InputObject $ascending) -DifferenceObject (ConvertTo-CanonicalJson -InputObject $descending)

            # Assert
            $difference | Should -BeNullOrEmpty
        }
    }

    Context 'Positive: a mixed document serializes to one exact canonical text' {

        It 'serializes objects, arrays, numbers, booleans, nulls and non-ASCII strings canonically' {
            # Arrange
            $document = [ordered]@{
                zeta    = 'Ünïcødé'
                alpha   = [ordered]@{ nested = @(3, 1, 2); flag = $false }
                middle  = $null
                count   = 42
                ratio   = 1.5
                list    = @('b', 'a')
                enabled = $true
            }

            # Act
            $canonical = ConvertTo-CanonicalJson -InputObject $document

            # Assert
            $canonical | Should -BeExactly '{"alpha":{"flag":false,"nested":[3,1,2]},"count":42,"enabled":true,"list":["b","a"],"middle":null,"ratio":1.5,"zeta":"Ünïcødé"}'
        }
    }
}
