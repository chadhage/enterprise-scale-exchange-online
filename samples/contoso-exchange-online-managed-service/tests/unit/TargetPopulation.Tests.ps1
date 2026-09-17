#requires -Version 7.0

BeforeAll {
    $script:SampleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:CommonModulePath = Join-Path $script:SampleRoot 'scripts' 'ExchangeOnlineBaseline.Common.psm1'

    # ExchangeOnlineManagement and Microsoft.Graph are not installed and must never be imported.
    # Every recipient record here is canned, exactly as a collector would hand it over.
    Import-Module -Name $script:CommonModulePath -Force -DisableNameChecking -ErrorAction Stop

    $script:StandardDomain = @('contoso.example', 'contoso-mail.example')

    $script:PriorityUser = 'priority.user@contoso.example'
    $script:StandardUser = 'standard.user@contoso.example'
    $script:SharedMailbox = 'shared.mailbox@contoso.example'
    $script:RoomMailbox = 'room.one@contoso.example'
    $script:EquipmentMailbox = 'equipment.one@contoso.example'
    $script:GuestUser = 'guest.user@partner.example'
    $script:MailUser = 'mail.user@contoso.example'
    $script:InactiveUser = 'inactive.user@contoso.example'
    $script:ExcludedUser = 'excluded.user@contoso.example'
    $script:UnlicensedUser = 'unlicensed.user@contoso.example'
    $script:UnmanagedUser = 'external.user@fabrikam.example'

    function New-Recipient {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [string]$UserPrincipalName,

            [string]$PrimarySmtpAddress,
            [string]$RecipientTypeDetails = 'UserMailbox',
            [string]$UserType = 'Member',
            [bool]$AccountEnabled = $true,
            [bool]$IsLicensed = $true,
            [string[]]$Omit = @()
        )

        $record = [ordered]@{
            userPrincipalName    = $UserPrincipalName
            primarySmtpAddress   = if ($PSBoundParameters.ContainsKey('PrimarySmtpAddress')) { $PrimarySmtpAddress } else { $UserPrincipalName }
            recipientTypeDetails = $RecipientTypeDetails
            userType             = $UserType
            accountEnabled       = $AccountEnabled
            isLicensed           = $IsLicensed
        }

        foreach ($name in $Omit) { $record.Remove($name) }

        return [pscustomobject]$record
    }

    # The representative population: one recipient for each class the card names, plus a recipient
    # in a domain the managed service does not accept.
    function New-RepresentativePopulation {
        [CmdletBinding()]
        param()

        return @(
            New-Recipient -UserPrincipalName $script:PriorityUser
            New-Recipient -UserPrincipalName $script:StandardUser
            New-Recipient -UserPrincipalName $script:SharedMailbox -RecipientTypeDetails 'SharedMailbox' -IsLicensed $false
            New-Recipient -UserPrincipalName $script:RoomMailbox -RecipientTypeDetails 'RoomMailbox' -IsLicensed $false
            New-Recipient -UserPrincipalName $script:EquipmentMailbox -RecipientTypeDetails 'EquipmentMailbox' -IsLicensed $false
            New-Recipient -UserPrincipalName $script:GuestUser -RecipientTypeDetails 'GuestMailUser' -UserType 'Guest' -IsLicensed $false
            New-Recipient -UserPrincipalName $script:MailUser -RecipientTypeDetails 'MailUser' -IsLicensed $false
            New-Recipient -UserPrincipalName $script:InactiveUser -AccountEnabled $false
            New-Recipient -UserPrincipalName $script:ExcludedUser
            New-Recipient -UserPrincipalName $script:UnlicensedUser -IsLicensed $false
            New-Recipient -UserPrincipalName $script:UnmanagedUser
        )
    }

    function Get-RecipientVerdict {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory)]
            [object]$Population,

            [Parameter(Mandatory)]
            [string]$UserPrincipalName
        )

        $match = @($Population.Recipient | Where-Object { $_.UserPrincipalName -eq $UserPrincipalName })
        if ($match.Count -ne 1) { return "NoSingleVerdict($($match.Count))" }

        return '{0}:{1}:{2}:{3}' -f $match[0].Classification, $match[0].Profile, $match[0].InScope, $match[0].LicensingRequired
    }
}

AfterAll {
    Remove-Module -Name 'ExchangeOnlineBaseline.Common' -Force -ErrorAction SilentlyContinue
}

Describe 'LIC-005-A target population classification' {

    BeforeEach {
        $script:Population = New-RepresentativePopulation
        $script:PriorityMember = @($script:PriorityUser)
        $script:Exclusion = @($script:ExcludedUser)
    }

    Context 'Negative: the population inputs must be usable' {

        It 'refuses a classification with no recipient' {
            # Arrange
            $emptyPopulation = @()

            # Act
            $classify = { Get-BaselineTargetPopulation -Recipient $emptyPopulation -StandardDomain $script:StandardDomain -PriorityGroupMember $script:PriorityMember -ExcludedRecipient $script:Exclusion }

            # Assert
            $classify | Should -Throw -ExpectedMessage 'RecipientRequired*' -Because 'an empty population is not a tenant with nobody in it'
        }

        It 'refuses a classification with no Standard domain' {
            # Arrange
            $noDomain = @()

            # Act
            $classify = { Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $noDomain -PriorityGroupMember $script:PriorityMember -ExcludedRecipient $script:Exclusion }

            # Assert
            $classify | Should -Throw -ExpectedMessage 'StandardDomainRequired*' -Because 'with no accepted domain every recipient would silently fall out of scope'
        }

        It 'refuses a blank Standard domain' {
            # Arrange
            $blankDomain = @('contoso.example', '   ')

            # Act
            $classify = { Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $blankDomain -PriorityGroupMember $script:PriorityMember -ExcludedRecipient $script:Exclusion }

            # Assert
            $classify | Should -Throw -ExpectedMessage 'StandardDomainNotADomain*' -Because 'a blank domain matches nothing and hides a configuration error'
        }

        It 'refuses a blank priority-group member' {
            # Arrange
            $blankMember = @($script:PriorityUser, '   ')

            # Act
            $classify = { Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $blankMember -ExcludedRecipient $script:Exclusion }

            # Assert
            $classify | Should -Throw -ExpectedMessage 'PriorityGroupMemberNotAUserPrincipalName*' -Because 'a blank member silently shrinks the Strict population'
        }

        It 'refuses a blank exclusion' {
            # Arrange
            $blankExclusion = @($script:ExcludedUser, '   ')

            # Act
            $classify = { Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $script:PriorityMember -ExcludedRecipient $blankExclusion }

            # Assert
            $classify | Should -Throw -ExpectedMessage 'ExcludedRecipientNotAUserPrincipalName*' -Because 'a blank exclusion cannot be reviewed or approved'
        }

        It 'refuses a duplicated recipient' {
            # Arrange
            $duplicated = @($script:Population) + @(New-Recipient -UserPrincipalName $script:StandardUser)

            # Act
            $classify = { Get-BaselineTargetPopulation -Recipient $duplicated -StandardDomain $script:StandardDomain -PriorityGroupMember $script:PriorityMember -ExcludedRecipient $script:Exclusion }

            # Assert
            $classify | Should -Throw -ExpectedMessage 'RecipientDuplicated*' -Because 'one recipient counted twice makes the licensing matrix depend on the collection order'
        }
    }

    Context 'Negative: the recipient record must be usable' {

        It 'refuses a recipient that omits a required member' -ForEach @(
            @{ Member = 'userPrincipalName' }
            @{ Member = 'primarySmtpAddress' }
            @{ Member = 'recipientTypeDetails' }
            @{ Member = 'userType' }
            @{ Member = 'accountEnabled' }
            @{ Member = 'isLicensed' }
        ) {
            # Arrange
            $incomplete = @(New-Recipient -UserPrincipalName $script:StandardUser -Omit @($Member))

            # Act
            $classify = { Get-BaselineTargetPopulation -Recipient $incomplete -StandardDomain $script:StandardDomain -PriorityGroupMember $script:PriorityMember -ExcludedRecipient $script:Exclusion }

            # Assert
            $classify | Should -Throw -ExpectedMessage "RecipientContractViolation*$Member*" -Because "a recipient without '$Member' cannot be classified"
        }

        It 'refuses a recipient type outside the declared vocabulary' {
            # Arrange
            $unknownType = @(New-Recipient -UserPrincipalName $script:StandardUser -RecipientTypeDetails 'PublicFolderMailbox')

            # Act
            $classify = { Get-BaselineTargetPopulation -Recipient $unknownType -StandardDomain $script:StandardDomain -PriorityGroupMember $script:PriorityMember -ExcludedRecipient $script:Exclusion }

            # Assert
            $classify | Should -Throw -ExpectedMessage 'UnknownRecipientTypeDetails*' -Because 'an unrecognized recipient type must never be guessed into a protected mailbox'
        }

        It 'refuses a user type outside the declared vocabulary' {
            # Arrange
            $unknownUserType = @(New-Recipient -UserPrincipalName $script:StandardUser -UserType 'Contractor')

            # Act
            $classify = { Get-BaselineTargetPopulation -Recipient $unknownUserType -StandardDomain $script:StandardDomain -PriorityGroupMember $script:PriorityMember -ExcludedRecipient $script:Exclusion }

            # Assert
            $classify | Should -Throw -ExpectedMessage 'UnknownUserType*' -Because 'an unrecognized user type must never be guessed into a tenant member'
        }
    }

    Context 'Negative: precedence between classes is fixed' {

        It 'does not let priority-group membership override an explicit exclusion' {
            # Arrange
            $priorityAndExcluded = @($script:PriorityUser, $script:ExcludedUser)

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityAndExcluded -ExcludedRecipient $script:Exclusion

            # Assert
            Get-RecipientVerdict -Population $population -UserPrincipalName $script:ExcludedUser |
                Should -Be 'ExplicitlyExcluded:None:False:False' -Because 'an approved exclusion is a deliberate decision and outranks group membership'
        }

        It 'does not target an explicitly excluded recipient for licensing' {
            # Arrange
            $priorityAndExcluded = @($script:PriorityUser, $script:ExcludedUser)

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityAndExcluded -ExcludedRecipient $script:Exclusion

            # Assert
            @($population.LicensingTarget) | Should -Not -Contain $script:ExcludedUser -Because 'a recipient the baseline does not protect must not be required to hold a licence for it'
        }

        It 'does not assign the Standard profile to a priority-group member' {
            # Arrange
            $priorityMember = $script:PriorityMember

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityMember -ExcludedRecipient $script:Exclusion

            # Assert
            Get-RecipientVerdict -Population $population -UserPrincipalName $script:PriorityUser |
                Should -Be 'StrictPriority:Strict:True:True' -Because 'a priority identity in an accepted domain qualifies for both profiles and Strict must win'
        }
    }

    Context 'Negative: recipients the baseline does not target stay out of scope' {

        It 'does not bring a guest into scope' {
            # Arrange
            $priorityMember = $script:PriorityMember

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityMember -ExcludedRecipient $script:Exclusion

            # Assert
            Get-RecipientVerdict -Population $population -UserPrincipalName $script:GuestUser |
                Should -Be 'Guest:None:False:False' -Because 'a guest holds no mailbox in this tenant and cannot be protected by its policies'
        }

        It 'does not bring a mail user into scope' {
            # Arrange
            $priorityMember = $script:PriorityMember

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityMember -ExcludedRecipient $script:Exclusion

            # Assert
            Get-RecipientVerdict -Population $population -UserPrincipalName $script:MailUser |
                Should -Be 'MailUser:None:False:False' -Because 'a mail user is a forwarding address, not a mailbox the baseline can harden'
        }

        It 'does not target an inactive recipient for licensing' {
            # Arrange
            $priorityMember = $script:PriorityMember

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityMember -ExcludedRecipient $script:Exclusion

            # Assert
            Get-RecipientVerdict -Population $population -UserPrincipalName $script:InactiveUser |
                Should -Be 'InactiveUser:None:False:False' -Because 'a disabled account cannot sign in and must not fail a licensing gate for the whole tenant'
        }

        It 'does not bring a recipient in an unmanaged domain into scope' {
            # Arrange
            $priorityMember = $script:PriorityMember

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityMember -ExcludedRecipient $script:Exclusion

            # Assert
            Get-RecipientVerdict -Population $population -UserPrincipalName $script:UnmanagedUser |
                Should -Be 'UnmanagedDomain:None:False:False' -Because 'the managed service does not accept that domain and must not claim to protect it'
        }

        It 'does not match a Standard domain by suffix' {
            # Arrange
            $lookalike = @(New-Recipient -UserPrincipalName 'attacker@notcontoso.example')

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $lookalike -StandardDomain $script:StandardDomain -PriorityGroupMember @() -ExcludedRecipient @()

            # Assert
            Get-RecipientVerdict -Population $population -UserPrincipalName 'attacker@notcontoso.example' |
                Should -Be 'UnmanagedDomain:None:False:False' -Because 'a domain is matched whole, so a look-alike domain never inherits the accepted domain scope'
        }
    }

    Context 'Negative: a mailbox that cannot hold a licence is never asked to' {

        It 'does not require a per-user licence for a resource mailbox' -ForEach @(
            @{ Mailbox = 'shared.mailbox@contoso.example' }
            @{ Mailbox = 'room.one@contoso.example' }
            @{ Mailbox = 'equipment.one@contoso.example' }
        ) {
            # Arrange
            $priorityMember = $script:PriorityMember

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityMember -ExcludedRecipient $script:Exclusion

            # Assert
            Get-RecipientVerdict -Population $population -UserPrincipalName $Mailbox |
                Should -Be 'ResourceMailbox:Standard:True:False' -Because 'a resource mailbox is protected by policy but holds no per-user licence to prove'
        }

        It 'does not report an unlicensed mailbox as a licensing target' {
            # Arrange
            $priorityMember = $script:PriorityMember

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityMember -ExcludedRecipient $script:Exclusion

            # Assert
            @($population.LicensingTarget) | Should -Not -Contain $script:UnlicensedUser -Because 'evaluating service plans for a mailbox that holds no licence only restates what is already known'
        }

        It 'does not drop an unlicensed mailbox instead of recording it as an exception' {
            # Arrange
            $priorityMember = $script:PriorityMember

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityMember -ExcludedRecipient $script:Exclusion

            # Assert
            @($population.Exception | ForEach-Object { $_.UserPrincipalName }) | Should -Be @($script:UnlicensedUser) -Because 'an unlicensed mailbox in an accepted domain is an exception that needs approval, not a recipient to forget'
        }
    }

    Context 'Negative: matching is case-insensitive' {

        It 'does not treat a differently-cased domain as unmanaged' {
            # Arrange
            $mixedCase = @(New-Recipient -UserPrincipalName 'Standard.User@CONTOSO.Example')

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $mixedCase -StandardDomain $script:StandardDomain -PriorityGroupMember @() -ExcludedRecipient @()

            # Assert
            Get-RecipientVerdict -Population $population -UserPrincipalName 'Standard.User@CONTOSO.Example' |
                Should -Be 'StandardDomain:Standard:True:True' -Because 'domain case carries no meaning in SMTP and must not decide scope'
        }

        It 'does not treat a differently-cased priority-group member as Standard' {
            # Arrange
            $mixedCaseMember = @('PRIORITY.USER@Contoso.Example')

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $mixedCaseMember -ExcludedRecipient $script:Exclusion

            # Assert
            Get-RecipientVerdict -Population $population -UserPrincipalName $script:PriorityUser |
                Should -Be 'StrictPriority:Strict:True:True' -Because 'a user principal name is case-insensitive and must not silently drop out of the Strict population'
        }
    }

    Context 'Negative: classification stays offline' {

        # The stubs are global, so cleanup must survive an Act that throws; otherwise a failing
        # run leaks them into the session and every later test resolves them instead of failing.
        AfterEach {
            Remove-Item -Path 'function:global:Connect-MgGraph', 'function:global:Get-MgUser', 'function:global:Get-Recipient', 'function:global:Get-Mailbox' -ErrorAction SilentlyContinue
        }

        It 'reaches Graph and Exchange Online only through the supplied recipients' {
            # Arrange
            $script:PopulationCommandInvocation = [System.Collections.Generic.List[string]]::new()
            function global:Connect-MgGraph { $script:PopulationCommandInvocation.Add('Connect-MgGraph') }
            function global:Get-MgUser { $script:PopulationCommandInvocation.Add('Get-MgUser') }
            function global:Get-Recipient { $script:PopulationCommandInvocation.Add('Get-Recipient') }
            function global:Get-Mailbox { $script:PopulationCommandInvocation.Add('Get-Mailbox') }

            # Act
            $null = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $script:PriorityMember -ExcludedRecipient $script:Exclusion

            # Assert
            $script:PopulationCommandInvocation | Should -BeNullOrEmpty -Because 'classification decides on the evidence it was handed and never collects more of its own accord'
        }
    }

    Context 'Positive: a representative population is classified whole' {

        It 'yields one classification, profile, scope and licensing decision per recipient with exact licensing-target and exception sets' {
            # Arrange
            $priorityMember = $script:PriorityMember

            # Act
            $population = Get-BaselineTargetPopulation -Recipient $script:Population -StandardDomain $script:StandardDomain -PriorityGroupMember $priorityMember -ExcludedRecipient $script:Exclusion

            # Assert
            $summary = @(
                @($population.Recipient | ForEach-Object { '{0}={1}:{2}:{3}:{4}' -f $_.UserPrincipalName, $_.Classification, $_.Profile, $_.InScope, $_.LicensingRequired }) -join '|'
                'Strict=' + (@($population.Strict) -join ',')
                'Standard=' + (@($population.Standard) -join ',')
                'LicensingTarget=' + (@($population.LicensingTarget) -join ',')
                'Exception=' + (@($population.Exception | ForEach-Object { $_.UserPrincipalName }) -join ',')
            ) -join '; '

            $summary | Should -Be (@(
                    @(
                        'priority.user@contoso.example=StrictPriority:Strict:True:True'
                        'standard.user@contoso.example=StandardDomain:Standard:True:True'
                        'shared.mailbox@contoso.example=ResourceMailbox:Standard:True:False'
                        'room.one@contoso.example=ResourceMailbox:Standard:True:False'
                        'equipment.one@contoso.example=ResourceMailbox:Standard:True:False'
                        'guest.user@partner.example=Guest:None:False:False'
                        'mail.user@contoso.example=MailUser:None:False:False'
                        'inactive.user@contoso.example=InactiveUser:None:False:False'
                        'excluded.user@contoso.example=ExplicitlyExcluded:None:False:False'
                        'unlicensed.user@contoso.example=UnlicensedMailbox:Standard:True:False'
                        'external.user@fabrikam.example=UnmanagedDomain:None:False:False'
                    ) -join '|'
                    'Strict=priority.user@contoso.example'
                    'Standard=standard.user@contoso.example,shared.mailbox@contoso.example,room.one@contoso.example,equipment.one@contoso.example,unlicensed.user@contoso.example'
                    'LicensingTarget=priority.user@contoso.example,standard.user@contoso.example'
                    'Exception=unlicensed.user@contoso.example'
                ) -join '; ') -Because 'every class the managed service recognizes is decided once, by the same rules, in the order the recipients were collected'
        }
    }
}
