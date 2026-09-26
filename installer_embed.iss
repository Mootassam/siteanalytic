; Website Intelligence installer — ships the official, digitally signed Python runtime
; (Python Software Foundation) with the app, so Windows Smart App Control can verify it.
; Build: stage build_embed\ (runtime\ + app\), then ISCC installer_embed.iss

#define MyAppName "Website Intelligence"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "Website Intelligence"

[Setup]
AppId={{B4B7B4E2-91A2-4C77-9F1D-WEBSITEINTEL20}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Website Intelligence
DisableProgramGroupPage=yes
LicenseFile=TERMS.txt
OutputDir=installer_output
OutputBaseFilename=WebsiteIntelligence-Setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
SetupIconFile=assets\icon.ico
UninstallDisplayIcon={app}\app\icon.ico
CloseApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; Flags: checkedonce

[Files]
Source: "build_embed\runtime\*"; DestDir: "{app}\runtime"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "build_embed\app\*"; DestDir: "{app}\app"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\runtime\pythonw.exe"; Parameters: """{app}\app\server.py"""; WorkingDir: "{app}\app"; IconFilename: "{app}\app\icon.ico"; Comment: "Full technical profile of any website — public data only"
Name: "{userdesktop}\{#MyAppName}"; Filename: "{app}\runtime\pythonw.exe"; Parameters: """{app}\app\server.py"""; WorkingDir: "{app}\app"; IconFilename: "{app}\app\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\runtime\pythonw.exe"; Parameters: """{app}\app\server.py"""; WorkingDir: "{app}\app"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[Code]
procedure StopWI(Dir: String);
var Rc: Integer; Cmd: String;
begin
  Cmd := '-NoProfile -ExecutionPolicy Bypass -Command "Get-Process python,pythonw -ErrorAction SilentlyContinue | ' +
         'Where-Object { $_.Path -and $_.Path.ToLower().StartsWith(''' + Lowercase(Dir) + ''') } | ' +
         'Stop-Process -Force -ErrorAction SilentlyContinue; Start-Sleep -Milliseconds 800"';
  Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Cmd, '', SW_HIDE, ewWaitUntilTerminated, Rc);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopWI(ExpandConstant('{app}'));
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  StopWI(ExpandConstant('{app}'));
  Result := True;
end;

[UninstallDelete]
; program files only — scans in Documents\Website Intelligence are never touched
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\runtime"
Type: dirifempty; Name: "{app}"
