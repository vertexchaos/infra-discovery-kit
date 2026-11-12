# Read-only Active Directory collector.
# Uses built-in .NET System.DirectoryServices, so RSAT / the ActiveDirectory module is not required.

function Get-IdkLdapCount {
    param([string]$SearchRoot, [string]$Filter)
    $root = if ($SearchRoot) { [ADSI]"LDAP://$SearchRoot" } else { $null }
    $searcher = if ($root) { New-Object System.DirectoryServices.DirectorySearcher($root) } else { New-Object System.DirectoryServices.DirectorySearcher }
    $searcher.Filter = $Filter
    $searcher.PageSize = 1000
    [void]$searcher.PropertiesToLoad.Add('distinguishedName')
    $results = $searcher.FindAll()
    try { return $results.Count } finally { $results.Dispose() }
}

# Prefer a routable IPv4 address; .NET's DomainController.IPAddress returns whatever DNS lists first (often IPv6 link-local).
function Get-IdkHostAddresses {
    param([string]$HostName, [string]$Fallback)
    $all = @()
    try { $all = @([System.Net.Dns]::GetHostAddresses($HostName) | ForEach-Object { $_.IPAddressToString }) } catch { }
    $v4 = @($all | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' -and $_ -notlike '169.254.*' -and $_ -notlike '127.*' })
    $primary = if ($v4.Count -gt 0) { $v4[0] } else { $Fallback }
    [ordered]@{ ip = $primary; ip_all = $all }
}

function Get-IdkActiveDirectory {
    param([int]$StaleDays = 90)

    $errors = New-Object System.Collections.ArrayList
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $data = [ordered]@{}

    $data.forest = [ordered]@{
        name            = $forest.Name
        mode            = [string]$forest.ForestMode
        mode_level      = $forest.ForestModeLevel
        schema_master   = $forest.SchemaRoleOwner.Name
        naming_master   = $forest.NamingRoleOwner.Name
        domains         = @($forest.Domains | ForEach-Object { $_.Name })
        global_catalogs = @($forest.GlobalCatalogs | ForEach-Object { $_.Name })
    }

    $data.domains = @(foreach ($d in $forest.Domains) {
        $dcs = @(foreach ($dc in $d.DomainControllers) {
            $entry = Invoke-IdkStep -Name "dc.$($dc.Name)" -Errors $errors -Script {
                $addr = Get-IdkHostAddresses -HostName $dc.Name -Fallback $dc.IPAddress
                [ordered]@{
                    name  = $dc.Name
                    ip    = $addr.ip
                    ip_all = $addr.ip_all
                    os    = $dc.OSVersion
                    site  = $dc.SiteName
                    is_gc = $dc.IsGlobalCatalog()
                    roles = @($dc.Roles | ForEach-Object { [string]$_ })
                }
            }
            if ($entry) { $entry } else { [ordered]@{ name = $dc.Name; unreachable = $true } }
        })
        $trusts = Invoke-IdkStep -Name "trusts.$($d.Name)" -Errors $errors -Script {
            @(foreach ($t in $d.GetAllTrustRelationships()) {
                [ordered]@{ target = $t.TargetName; direction = [string]$t.TrustDirection; type = [string]$t.TrustType }
            })
        }
        [ordered]@{
            name                  = $d.Name
            mode                  = [string]$d.DomainMode
            mode_level            = $d.DomainModeLevel
            pdc_emulator          = $d.PdcRoleOwner.Name
            rid_master            = $d.RidRoleOwner.Name
            infrastructure_master = $d.InfrastructureRoleOwner.Name
            domain_controllers    = $dcs
            trusts                = @($trusts)
        }
    })

    $data.sites = @(foreach ($s in $forest.Sites) {
        [ordered]@{
            name       = $s.Name
            subnets    = @($s.Subnets | ForEach-Object { $_.Name })
            servers    = @($s.Servers | ForEach-Object { $_.Name })
            site_links = @($s.SiteLinks | ForEach-Object { $_.Name })
        }
    })

    # Account hygiene counts for the domain this host belongs to.
    $data.accounts = Invoke-IdkStep -Name 'accounts' -Errors $errors -Script {
        $cutoff = (Get-Date).AddDays(-$StaleDays).ToFileTimeUtc()
        $enabledUser = '(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        $enabledComputer = '(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
        $stale = "(|(lastLogonTimestamp<=$cutoff)(!(lastLogonTimestamp=*)))"
        [ordered]@{
            stale_days               = $StaleDays
            enabled_users            = Get-IdkLdapCount -Filter "(&$enabledUser)"
            stale_users              = Get-IdkLdapCount -Filter "(&$enabledUser$stale)"
            enabled_computers        = Get-IdkLdapCount -Filter "(&$enabledComputer)"
            stale_computers          = Get-IdkLdapCount -Filter "(&$enabledComputer$stale)"
            password_never_expires   = Get-IdkLdapCount -Filter "(&$enabledUser(userAccountControl:1.2.840.113556.1.4.803:=65536))"
            admincount_users         = Get-IdkLdapCount -Filter "(&$enabledUser(adminCount=1))"
        }
    }

    $data.gpo_count = Invoke-IdkStep -Name 'gpo_count' -Errors $errors -Script {
        $domainDn = ([ADSI]'LDAP://RootDSE').defaultNamingContext
        Get-IdkLdapCount -SearchRoot "CN=Policies,CN=System,$domainDn" -Filter '(objectClass=groupPolicyContainer)'
    }

    # Time source per DC. The PDC emulator should use a reliable external source; other DCs follow the domain hierarchy.
    $data.time = @(foreach ($d in $data.domains) {
        foreach ($dc in $d.domain_controllers) {
            $result = Invoke-IdkStep -Name "time.$($dc.name)" -Errors $errors -Script {
                Invoke-IdkNative -FilePath 'w32tm' -Arguments @('/query', "/computer:$($dc.name)", '/source')
            }
            [ordered]@{
                dc     = $dc.name
                is_pdc = ($dc.name -eq $d.pdc_emulator)
                source = if ($result -and $result.available) { $result.output } else { $null }
            }
        }
    })

    $pdc = $data.domains[0].pdc_emulator
    $data.native = [ordered]@{
        replsummary    = Invoke-IdkStep -Name 'repadmin' -Errors $errors -Script { Invoke-IdkNative -FilePath 'repadmin' -Arguments @('/replsummary') }
        dfsr_state     = Invoke-IdkStep -Name 'dfsrmig' -Errors $errors -Script { Invoke-IdkNative -FilePath 'dfsrmig' -Arguments @('/getglobalstate') }
        dcdiag         = Invoke-IdkStep -Name 'dcdiag' -Errors $errors -Script { Invoke-IdkNative -FilePath 'dcdiag' -Arguments @('/q', "/s:$pdc") }
    }

    return @{ data = $data; errors = $errors }
}
