# AD-Azure-Stale-Computer-Discover
This pulls "stale" computer objects from AD and then takes the identified devices and compares it to Activity data in MS Entra removing those Stale assets that show as active in the Azure query.

The variables in this script are:
$StaleCutoffDays- Cutoff defines the minimum time window for Objects to be "Stale"
$TenantId- You'll need this for the Entra query 
$Domains - Domains in the same AD forest you want to query.
