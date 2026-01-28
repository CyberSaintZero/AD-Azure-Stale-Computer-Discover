# AD-Azure-Stale-Computer-Discover
This pulls Stale computer objects from AD and removes discovered Assets that active in Entra
The variables in this script are:
$StaleCutoffDays- Cutoff defines the minimum time window for Objects to be "Stale"
$TenantId- You'll need this for the Entra query 
$Domains - Domains in the same AD forest you want to query.
