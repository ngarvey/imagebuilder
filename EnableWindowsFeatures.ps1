
############################################################
# Script to install the community edition of docker on Windows
############################################################

<#
    .NOTES
        Copyright (c) Microsoft Corporation.  All rights reserved.

        Use of this sample source code is subject to the terms of the Microsoft
        license agreement under which you licensed this sample source code. If
        you did not accept the terms of the license agreement, you are not
        authorized to use this sample source code. For the terms of the license,
        please see the license agreement between you and Microsoft or, if applicable,
        see the LICENSE.RTF on your install media or the root of your tools installation.
        THE SAMPLE SOURCE CODE IS PROVIDED "AS IS", WITH NO WARRANTIES.

    .SYNOPSIS
        Installs the prerequisites for creating Windows containers

    .DESCRIPTION
        Installs the prerequisites for creating Windows containers

    .PARAMETER Force 
        If a restart is required, forces an immediate restart.
        
    .PARAMETER HyperV 
        If passed, prepare the machine for Hyper-V containers
        
    .PARAMETER NoRestart
        If a restart is required the script will terminate and will not reboot the machine

    .EXAMPLE
        .\Install-ContainerHost.ps1

#>
#Requires -Version 5.0

[CmdletBinding(DefaultParameterSetName="Standard")]
param(
    [switch]
    $Force,

    [switch]
    $HyperV,

    [switch]
    $NoRestart,

    [Parameter(DontShow)]
    [switch]
    $PSDirect
)

$global:RebootRequired = $false

$global:ErrorFile = "$pwd\Install-ContainerHost.err"

$global:BootstrapTask = "ContainerBootstrap"

$global:HyperVImage = "NanoServer"

function
Install-Feature
{
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string]
        $FeatureName
    )

    Write-Output "Querying status of Windows feature: $FeatureName..."
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)
    {
        if ((Get-WindowsFeature $FeatureName).Installed)
        {
            Write-Output "Feature $FeatureName is already enabled."
        }
        else
        {
            Test-Admin

            Write-Output "Enabling feature $FeatureName..."
        }

        $featureInstall = Add-WindowsFeature $FeatureName

        if ($featureInstall.RestartNeeded -eq "Yes")
        {
            $global:RebootRequired = $true;
        }
    }
    else
    {
        if ((Get-WindowsOptionalFeature -Online -FeatureName $FeatureName).State -eq "Disabled")
        {
            if (Test-Nano)
            {
                throw "This NanoServer deployment does not include $FeatureName.  Please add the appropriate package"
            }

            Test-Admin

            Write-Output "Enabling feature $FeatureName..."
            $feature = Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart

            if ($feature.RestartNeeded -eq "True")
            {
                $global:RebootRequired = $true;
            }
        }
        else
        {
            Write-Output "Feature $FeatureName is already enabled."

            if (Test-Nano)
            {
                #
                # Get-WindowsEdition is not present on Nano.  On Nano, we assume reboot is not needed
                #
            }
            elseif ((Get-WindowsEdition -Online).RestartNeeded)
            {
                $global:RebootRequired = $true;
            }
        }
    }
}

function
Install-ContainerHost
{
    "If this file exists when Install-ContainerHost.ps1 exits, the script failed!" | Out-File -FilePath $global:ErrorFile

    if (Test-Client)
    {
        if (-not $HyperV)
        {
            Write-Output "Enabling Hyper-V containers by default for Client SKU"
            $HyperV = $true
        }    
    }
    #
    # Validate required Windows features
    #
    Install-Feature -FeatureName Containers

    if ($HyperV)
    {
        Install-Feature -FeatureName Hyper-V
    }

    Remove-Item $global:ErrorFile

    Write-Output "Script complete!"
}

$global:AdminPriviledges = $false

function 
Test-Admin()
{
    # Get the ID and security principal of the current user account
    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
  
    # Get the security principal for the Administrator role
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
  
    # Check to see if we are currently running "as Administrator"
    if ($myWindowsPrincipal.IsInRole($adminRole))
    {
        $global:AdminPriviledges = $true
        return
    }
    else
    {
        #
        # We are not running "as Administrator"
        # Exit from the current, unelevated, process
        #
        throw "You must run this script as administrator"   
    }
}


function 
Test-Client()
{
    return (-not ((Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) -or (Test-Nano)))
}


function 
Test-Nano()
{
    $EditionId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID').EditionId

    return (($EditionId -eq "ServerStandardNano") -or 
            ($EditionId -eq "ServerDataCenterNano") -or 
            ($EditionId -eq "NanoServer") -or 
            ($EditionId -eq "ServerTuva"))
}

try
{
    Install-ContainerHost -NoRestart
}
catch 
{
    Write-Error $_
}