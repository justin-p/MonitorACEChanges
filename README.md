# MonitorACEChanges

**Please test this in a test environment before applying this in production.**

## Prerequisites

1. Create a GPO and follow this guide to apply the 'Baseline Recommendation' at minimum.  
https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations

2. Create a second GPO to enforce Advanced Auditing.  
https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/Monitoring-Active-Directory-for-Signs-of-Compromise#enforcing-traditional-auditing-or-advanced-auditing

3. Apply a SACL on the root of AD that monitors changes made to properties and permissions.  
![SACL](2020-11-04_17-08.png)

4. Apply GPO's to the Domain Controllers OU and reboot the domain controllers.  
![gpos](2020-11-04_16-52.png)

### Example: Get current SDDLs

`GetKnownGoods.ps1` will get SDDL's of all the current AD Objects. This example will exported these values to a XML file.

### Example: Use Eventvwr and known SDDL values to find 'out of place' ACEs.

By enabling auditing for `Directory Services Changes` and creating a SACL whenever a change is applied to a ACE of a AD Object this is now logged as EventID 5136. 
`MonitorEvents.ps1` uses these events and the previosly gathered SDDLs from `GetKnownGoods.ps1` as known good values to determine what changed from the previously known 'good' configuration.
