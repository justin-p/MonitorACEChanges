## Find Events with EventID 5136. Match the change with the known good state.

Function Return-Facts {
    Param (
        $Message,
        $Time = $event.TimeGenerated,
        $ObjectDN = $ObjectDN,
        $SubjectDomainName = $SubjectDomainName,
        $SubjectUserName = $SubjectUserName,
        $SubjectUserSid = $SubjectUserSid,
        $OperationType = $OperationType,
        $AttributeValue = $AttributeValue,
        $KnownGoodSDDL = $KnownGoodSDDL
    )
    if ($KnownGoodSDDL) {
        $KnownGoodDiscretionaryAcl = $((ConvertFrom-SddlString $KnownGoodSDDL).DiscretionaryAcl)
        $Diff = Compare-Object $((ConvertFrom-SddlString $AttributeValue).DiscretionaryAcl).split() $((ConvertFrom-SddlString $KnownGoodSDDL).DiscretionaryAcl).split()
    } Else {
        $KnownGoodDiscretionaryAcl = $Null
        $Diff = $Null
    }
    $NewDiscretionaryAcl = $((ConvertFrom-SddlString $AttributeValue).DiscretionaryAcl)
    
    if ($diff) {
        $WhatChanged = $(($Diff).InputObject)
    }
    ElseIf ($null -eq $KnownGoodDiscretionaryAcl) {
         $WhatChanged =  "No known good state, see NewDiscretionaryAcl and look for values that seem out of place."
    }
    ElseIf ($null -eq $diff) {
         $WhatChanged =  "Effective permissions are the same as the known good state."
    }


    Return (New-Object psobject -Property @{
        'TimeGenerated'             = $Time
        'Message'                   = $Message
        'Location'                  = $ObjectDN
        'ChangedBy'                 = $("$($SubjectDomainName)\$($SubjectUserName) ($($SubjectUserSid)")
        'Actions'                   = $OperationType
        'WhatChanged'               = $WhatChanged
        'NewDiscretionaryAcl'       = $NewDiscretionaryAcl
        'KnownGoodDiscretionaryAcl' = $KnownGoodDiscretionaryAcl
        'NewSDDL'                   = $AttributeValue
        'KnownGoodSDDL'             = $KnownGoodSDDL
    })
}

Function Check-ACLMismatches {
    [CmdletBinding()]
    Param (
        $KnownGoods,
        $Events
    )
    ForEach ($Event in $Events) {
        $OpCorrelationID          = $event.ReplacementStrings[0] 
        $AppCorrelationID         = $event.ReplacementStrings[1]
        $SubjectUserSid           = $event.ReplacementStrings[2]
        $SubjectUserName          = $event.ReplacementStrings[3]
        $SubjectDomainName        = $event.ReplacementStrings[4]
        $SubjectLogonId           = $event.ReplacementStrings[5]
        $DSName                   = $event.ReplacementStrings[6]
        $DSType                   = $event.ReplacementStrings[7]
        $ObjectDN                 = $event.ReplacementStrings[8]
        $ObjectGUID               = $event.ReplacementStrings[9]
        $ObjectClass              = $event.ReplacementStrings[10]
        $AttributeLDAPDisplayName = $event.ReplacementStrings[11]
        $AttributeSyntaxOID       = $event.ReplacementStrings[12]
        $AttributeValue           = $event.ReplacementStrings[13]
        $OperationType            = $event.ReplacementStrings[14]


        If ($OperationType -eq "%%14675") {
            $OperationType = "Value Deleted"
        } ElseIf ($OperationType -eq "%%14674") {
            $OperationType = "Value Added"
        } Else {
            # Unknown $OperationType, not updating the value to a friendly version.
        }
        
        $KnownGoodSDDL = $null
        If ($AttributeLDAPDisplayName -eq 'nTSecurityDescriptor') {
            If ($ObjectDN -in $KnownGoods.Location) {
                $KnownGoodSDDL = $($KnownGoods | Where-Object {$_.location -eq $ObjectDN }).SDDL
                If ($KnownGoodSDDL -ne $AttributeValue ) {
                    Return-Facts -Message "Found an ACL edit that mismatches with known good SDDL"
                }
            } Else { 
                Return-Facts -Message "Found an ACL edit on unknown location"
            }
        }    
    }
}

$KnownGoods = Import-Clixml -Path 'C:\Users\Administrator\Documents\MonitorACLChanges\KnownGoods.xml'
$Events     = Get-Eventlog Security | Where-Object {$_.EventID -eq 5136}
$Results    = Check-ACLMismatches -KnownGoods $KnownGoods -Events $Events

# Basic result
$results | ft TimeGenerated,Message,Location,Actions,ChangedBy,WhatChanged #NewDiscretionaryAcl,KnownGoodDiscretionaryAcl,NewSDDL,KnownGoodSDDL

## Full result
# $results | fl TimeGenerated,Message,Location,Actions,ChangedBy,WhatChanged,NewDiscretionaryAcl,KnownGoodDiscretionaryAcl,NewSDDL,KnownGoodSDDL
