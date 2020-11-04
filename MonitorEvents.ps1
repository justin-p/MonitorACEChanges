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
    $NewSDDLString       = ConvertFrom-SddlString $AttributeValue
    $NewDiscretionaryAcl = $NewSDDLString.DiscretionaryAcl
    if ($KnownGoodSDDL) {
        $KnownGoodSDDLString       = ConvertFrom-SddlString $KnownGoodSDDL
        $KnownGoodDiscretionaryAcl = $KnownGoodSDDLString.DiscretionaryAcl
        $Known_Object =@()
        $New_Object   =@()

        ForEach ($ACL in $NewSDDLString) {
            $owner  = $ACl.Owner 
            $group  = $ACl.Group
            $ACLobj = @()
            ForEach ($ACE in $ACL.DiscretionaryAcl) {
                $user   = $ACE.split(':')[0]
                $rights = $ACE.split(':')[1]
                $ACLobj+= (New-Object psobject -Property @{User = $user;Rights = $rights})                
            }
            $New_Object+= (New-Object psobject -Property @{State='New value';owner=$owner;group=$group;ACL=$ACLobj})                
        }

        ForEach ($ACL in $KnownGoodSDDLString) {
            $owner  = $ACl.Owner 
            $group  = $ACl.Group
            $ACLobj = @()
            ForEach ($ACE in $ACL.DiscretionaryAcl) {
                $user   = $ACE.split(':')[0]
                $rights = $ACE.split(':')[1]
                $ACLobj+= (New-Object psobject -Property @{User = $user;Rights = $rights})                
            }
            $Known_Object+= (New-Object psobject -Property @{State='Known good value';owner=$owner;group=$group;ACL=$ACLobj})                
        }


        $New   = (New-Object psobject -Property @{State=$New_Object.state;owner=$New_Object.owner;group=$New_Object.group;ACL=$($New_Object.acl | Sort-Object -Unique User,Rights)})
        $Known = (New-Object psobject -Property @{State=$Known_Object.state;owner=$Known_Object.owner;group=$Known_Object.group;ACL=$($Known_Object.acl | Sort-Object -Unique User,Rights)})
        
        
        $ACLDiff   = Compare-Object $Known.acl $New.acl -Property user,rights | Where-Object {$_.sideindicator -eq "=>"} | Select-Object user,rights
        $OwnerDiff = Compare-Object $Known $New -Property owner,group | Where-Object {$_.sideindicator -eq "=>"} | Select-Object owner,group
        $Diff      = (New-Object psobject -Property @{OwnerDiff=$OwnerDiff;ACLDiff=$ACLDiff;})
        
    } 
    Else {
        $KnownGoodDiscretionaryAcl = $Null
        $Diff = $Null
    }
        
    if ($diff) {
        $WhatChanged = (New-Object psobject -Property @{diff=$diff;new=$new;know=$known;}) 
    }
    ElseIf ($null -eq $KnownGoodDiscretionaryAcl) {
         $WhatChanged =  "No known good state, look for values that seem out of place."
    }
    ElseIf ($null -eq $diff) {
         $WhatChanged =  "Effective permissions are the same as the known good state."
    }

    Return (New-Object psobject -Property @{
        'TimeGenerated'             = $Time
        'Message'                   = $Message
        'Location'                  = $ObjectDN
        'ChangedBy'                 = $("$($SubjectDomainName)\$($SubjectUserName) ($($SubjectUserSid))")
        'Actions'                   = $OperationType
        'WhatChanged'               = $WhatChanged
        'NewDiscretionaryAcl'       = $NewDiscretionaryAcl
        'KnownGoodDiscretionaryAcl' = $KnownGoodDiscretionaryAcl
        'NewSDDL'                   = $AttributeValue
        'NewSDDLString'             = $NewSDDLString
        'KnownGoodSDDL'             = $KnownGoodSDDL
        'KnownGoodSDDLString'       = $KnownGoodSDDLString
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
                    Return-Facts -Message "ACL mismatches with known good state"
                }
            } Else { 
                Return-Facts -Message "ACL with no known good state"
            }
        }    
    }
}

$KnownGoods = Import-Clixml -Path 'C:\Users\Administrator\Documents\MonitorACLChanges\KnownGoods.xml'
$Events     = Get-Eventlog Security | Where-Object {$_.EventID -eq 5136} | Sort-Object Time
$Results    = Check-ACLMismatches -KnownGoods $KnownGoods -Events $Events

# Easy to read result
ForEach ($result in $Results) {
    Write-Host "[!] $($Result.Message)" -ForegroundColor Yellow
    Write-Host "    [-] The event was generated at: " -ForegroundColor Green -NoNewline
    Write-Host "$($result.TimeGenerated)"
    Write-Host "    [-] The object that was changed: " -ForegroundColor Green -NoNewline
    Write-Host "$($Result.Location)"    
    Write-Host "    [-] The user that changed the object was: " -ForegroundColor Green -NoNewline
    Write-Host "$($Result.ChangedBy)"
    Write-Host "    [-] The action that was taken: " -ForegroundColor Green -NoNewline
    Write-Host "$($Result.Actions)"
    if ($result.WhatChanged.GetType().Name -eq "string") {
        Write-Host "    $($result.WhatChanged)" -ForegroundColor Yellow
        $result.NewSDDLString | Select-Object owner,group,DiscretionaryAcl,SystemAcl| ConvertTo-Json -Depth 3
    } Else {
        Write-Host "    [-] Things that where changed: " -ForegroundColor Green
        if ($null -ne $result.WhatChanged.diff.OwnerDiff.Owner) {
            Write-Host "    [x] The owner of the object has been changed to: $($result.WhatChanged.diff.ownerdiff.Owner)" -ForegroundColor Red
        }
        if ($null -ne $result.WhatChanged.diff.ACLDiff.user) {
            ForEach ($entry in $result.WhatChanged.diff.ACLDiff) {
                Write-Host "    [x] A new ACE for user $($entry.user) has been added." -ForegroundColor Red
                Write-Host "        ACE Rights : $($entry.rights)" -ForegroundColor Red            
            }

        }
    }
    Write-Host "    "
}


## Full result
# $results | fl TimeGenerated,Message,Location,Actions,ChangedBy,WhatChanged,NewDiscretionaryAcl,KnownGoodDiscretionaryAcl,NewSDDL,KnownGoodSDDL
