# escape=`

FROM cirrusci/windowsservercore:cmake-2022.06.23
SHELL ["powershell", "-Command"]

ENV CIRRUS_SHELL="powershell"
ENV MSYS="winsymlinks:nativestrict"
ENV MSYSTEM="MINGW64"

ENV MSYS2_URL="https://github.com/msys2/msys2-installer/releases/download/2025-02-21/msys2-base-x86_64-20250221.sfx.exe"
ENV CHERE_INVOKING="1"

ENV MSYS2_PACKAGES="`
diffutils git grep make pkgconf sed `
mingw-w64-x86_64-binutils `
mingw-w64-x86_64-gcc `
mingw-w64-x86_64-cmake `
mingw-w64-x86_64-pkgconf `
mingw-w64-x86_64-capstone `
mingw-w64-i686-binutils `
mingw-w64-i686-gcc `
mingw-w64-i686-cmake `
mingw-w64-i686-pkgconf"

WORKDIR C:\tools

RUN Write-Host 'Creating directories...'; `
    md -Force C:\tools\archive\pkg; `
    Write-Host "Downloading MSYS2 from $env:MSYS2_URL..."; `
    bitsadmin /transfer msys_download /dynamic /download /priority FOREGROUND ${env:MSYS2_URL} C:\tools\archive\base.exe; `
    Write-Host 'Installing MSYS2 base...'; `
    .\archive\base.exe -y; `
    Write-Host 'Deleting MSYS2 installer...'; `
    del -Force .\archive\base.exe; `
    Write-Host 'Configuring MSYS2 post-install...'; `
    ((Get-Content -path .\msys64\etc\post-install\07-pacman-key.post -Raw) -replace '--refresh-keys', '--version') | Set-Content -Path .\msys64\etc\post-install\07-pacman-key.post; `
    Write-Host 'Disabling CheckSpace in pacman.conf...'; `
    .\msys64\usr\bin\bash.exe -lc ('"sed -i ''s/^CheckSpace/#CheckSpace/g'' /etc/pacman.conf"'); `
    Write-Host 'Updating MSYS2 core system (step 1 - pacman -Sy)...'; `
    .\msys64\usr\bin\pacman.exe --noconfirm -Sy; `
    Write-Host 'Updating MSYS2 core system (step 2 - pacman -Suu)...'; `
    Write-Output Y | .\msys64\usr\bin\pacman.exe --noconfirm -Suu --overwrite='*'; `
    Write-Host 'Attempting to kill any lingering msys-2.0.dll processes (best effort)...'; `
    try { taskkill /F /FI '"MODULES eq msys-2.0.dll"' } catch { Write-Host 'No msys-2.0.dll processes found or taskkill failed.' }; `
    tasklist; `
    Write-Host 'Applying pacman configuration updates and forcing further system update (pacman -Syyuu via bash)...'; `
    .\msys64\usr\bin\bash.exe -lc ('"mv -f /etc/pacman.conf.pacnew /etc/pacman.conf || true"'); `
    .\msys64\usr\bin\bash.exe -lc ('"pacman --noconfirm -Syyuu --overwrite=''*''"'); `
    $trimmed_packages = $env:MSYS2_PACKAGES.Trim(); `
    Write-Host "Installing MSYS2 packages: ---$trimmed_packages---"; `
    if (-not [string]::IsNullOrWhiteSpace($trimmed_packages)) { `
        .\msys64\usr\bin\bash.exe -lc ('"pacman --noconfirm -S --needed ' + $trimmed_packages + '"') `
    } else { `
        Write-Host 'MSYS2_PACKAGES is empty, skipping package installation.' `
    }; `
    Write-Host 'Cleaning up MSYS2 installation...'; `
    del -Force -ErrorAction SilentlyContinue .\msys64\etc\mtab; `
    del -Force -ErrorAction SilentlyContinue .\msys64\dev\fd; `
    del -Force -ErrorAction SilentlyContinue .\msys64\dev\stderr; `
    del -Force -ErrorAction SilentlyContinue .\msys64\dev\stdin; `
    del -Force -ErrorAction SilentlyContinue .\msys64\dev\stdout; `
    del -Force -Recurse -ErrorAction SilentlyContinue .\msys64\var\cache\pacman\pkg
