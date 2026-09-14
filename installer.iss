; Inno Setup script for Zenith compiler v2.0
; Download Inno Setup: https://jrsoftware.org/isdl.php
; Compile: right-click this file → Compile, or: iscc installer.iss

#define MyAppName "Zenith"
#define MyAppVersion "3.0"
#define MyAppPublisher "Zenith"
#define MyAppURL "https://github.com/zenith-lang/zenith"
#define MyAppExeName "zenith.exe"

[Setup]
AppId={{AFE5A3E1-7D3C-4B8A-9F1E-2C8D6F4B0A12}
AppName={#MyAppName} {#MyAppVersion}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName=C:\Program Files\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=.
OutputBaseFilename=Zenith-{#MyAppVersion}-Setup
SetupIconFile=
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
VersionInfoVersion=2.0.0.0
VersionInfoDescription={#MyAppName} Compiler {#MyAppVersion}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "path"; Description: "Add to PATH (system-wide)"; Flags: checkedonce
Name: "assoc"; Description: "Associate .z files with {#MyAppName}"; Flags: checkedonce
Name: "desktop"; Description: "Create desktop shortcut"; Flags: unchecked

[Files]
Source: "zenith.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "src\*"; DestDir: "{app}\src"; Flags: ignoreversion recursesubdirs skipifsourcedoesntexist
Source: "libs\libs.dll"; DestDir: "{app}\libs"; Flags: ignoreversion

[Dirs]
Name: "{app}\libs"; Flags: uninsalwaysuninstall

[Icons]
Name: "{group}\{#MyAppName} {#MyAppVersion}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{group}\Examples"; Filename: "{app}\examples"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktop

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Tasks: path; Check: NeedsAddPath(ExpandConstant('{app}'))

Root: HKCR; Subkey: ".z"; ValueType: string; ValueName: ""; ValueData: "ZenithSource"; \
    Flags: uninsdeletekey; Tasks: assoc
Root: HKCR; Subkey: "ZenithSource"; ValueType: string; ValueName: ""; ValueData: "Zenith Source File"; \
    Flags: uninsdeletekey; Tasks: assoc
Root: HKCR; Subkey: "ZenithSource\DefaultIcon"; ValueType: string; ValueName: ""; \
    ValueData: "{app}\{#MyAppExeName},0"; Tasks: assoc
Root: HKCR; Subkey: "ZenithSource\shell\open\command"; ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#MyAppExeName}"" ""%1"" -o ""%~n1.exe"""; Tasks: assoc

[Run]
Filename: "{app}\examples"; Description: "Open examples folder"; Flags: nowait postinstall skipifsilent shellexec

[Code]

function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKLM,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Param + ';', ';' + OrigPath + ';') = 0;
end;
