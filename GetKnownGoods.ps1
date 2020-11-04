## Get all SDDLs of the current AD Objects and store them as known good values.

Function Get-KnownGoods {
    Param (
        $Location
    )
    Set-Location AD:
    $ACL = Get-ACL $Location
    Return (New-Object psobject -Property @{Location=$Location;SDDL=$ACL.Sddl;})
}

Import-Module ActiveDirectory
$RootDN    = $(Get-ADDomain).DistinguishedName
$KnowGoods = @()
$ADObjects = Get-ADObject -Filter * -Properties DistinguishedName
ForEach ($Object in $ADObjects) {
    $KnowGoods += Get-KnownGoods -Location $Object.DistinguishedName
}
$KnowGoods | Export-Clixml "C:\Users\username\Documents\MonitorACLChanges\KnownGoods.xml"
