@{
    IncludeDefaultRules = $true
    Rules               = @{
        PSUseConsistentIndentation         = @{
            Enable              = $true
            Kind                = 'space'
            IndentationSize     = 4
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
        }
        PSUseConsistentWhitespace          = @{
            Enable                                  = $true
            CheckOpenBrace                          = $true
            CheckOpenParen                          = $true
            CheckOperator                           = $false
            CheckSeparator                          = $true
            IgnoreAssignmentOperatorInsideHashTable = $true
        }
        PSUseCompatibleCmdlets             = @{
            compatibility = @(
                'desktop-5.1.14393.206-windows'
            )
        }
        PSUseCompatibleCommands            = @{
            Enable         = $true
            TargetProfiles = @(
                'win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework'
            )
            IgnoreCommands = @()
        }
        PSUseCompatibleSyntax              = @{
            Enable         = $true
            TargetVersions = @(
                '5.1'
            )
        }
        PSUseCompatibleTypes               = @{
            Enable         = $true
            TargetProfiles = @(
                'win-8_x64_10.0.14393.0_5.1.14393.2791_x64_4.0.30319.42000_framework'
            )
            # You can specify types to not check like this, which will also ignore methods and members on it:
            IgnoreTypes    = @(
                'System.IO.Compression.ZipFile'
            )
        }
        PSUseCorrectCasing                 = @{
            Enable = $true
        }
        PSAvoidUsingPositionalParameters   = @{
            Enable           = $true
            CommandAllowList = 'Join-Path'
        }
        PSAvoidExclaimOperator             = @{
            Enable = $true
        }
        PSAvoidSemicolonsAsLineTerminators = @{
            Enable = $true
        }
        PSPlaceCloseBrace                  = @{
            Enable             = $true
            NoEmptyLineBefore  = $true
            IgnoreOneLineBlock = $true
            NewLineAfter       = $false
        }
        PSPlaceOpenBrace                   = @{
            Enable             = $true
            OnSameLine         = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }
        PSProvideCommentHelp               = @{
            Enable                  = $true
            ExportedOnly            = $false
            BlockComment            = $true
            VSCodeSnippetCorrection = $true
            Placement               = 'begin'
        }
    }
    CustomRulePath      = 'AdditionalPssaRules.psm1'
    ExcludeRules        = @(
        'PSAvoidUsingWriteHost'
        'PSAvoidUsingCmdletAliases'
        'PSAvoidUsingDoubleQuotesForConstantString'
        # 'PSAvoidUsingPlainTextForPassword'  # Discuss with team
        # 'PSAvoidUsingUsernameAndPasswordParams'  # Discuss with team
        'PSAvoidDefaultValueForMandatoryParameter'
        # 'PSPossibleIncorrectUsageOfAssignmentOperator'  # https://github.com/PowerShell/PSScriptAnalyzer/blob/main/docs/Rules/PossibleIncorrectUsageOfAssignmentOperator.md#implicit-suppression-using-clang-style
        # 'PSUseSingularNouns  # [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', 'Get-Elements')]
    )
}